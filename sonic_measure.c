/*
 * SONiC Attestation System - C Measurement Collector
 * sonic_measure.c
 *
 * High-performance measurement collection for system components
 * Compiles with: gcc -o sonic_measure sonic_measure.c -lcrypto -ljson-c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <dirent.h>
#include <time.h>
#include <errno.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <json-c/json.h>
#include <stdarg.h>

#define MAX_PATH 4096
#define MAX_BUFFER 65536
#define SHA256_DIGEST_SIZE 32
#define SHA256_HEX_SIZE 65

/* Logging levels */
typedef enum
{
    LOG_ERROR = 0,
    LOG_WARN = 1,
    LOG_INFO = 2,
    LOG_DEBUG = 3
} log_level_t;

/* Measurement structure */
typedef struct
{
    char component[64];
    char subcomponent[64];
    char hash[SHA256_HEX_SIZE];
    char description[256];
    time_t timestamp;
} measurement_t;

/* Measurements collection */
typedef struct
{
    measurement_t *measurements;
    size_t count;
    size_t capacity;
} measurement_collection_t;

/* Global variables */
static log_level_t current_log_level = LOG_INFO;
static FILE *log_file = NULL;

/* Function declarations */
int init_logging(const char *log_path);
void log_message(log_level_t level, const char *format, ...);
int hash_file(const char *filepath, char *hash_output);
int hash_string(const char *data, char *hash_output);
char *read_file_content(const char *filepath);
char *execute_command(const char *command);
measurement_collection_t *init_measurements(void);
int add_measurement(measurement_collection_t *collection, const char *component,
                    const char *subcomponent, const char *hash, const char *description);
void free_measurements(measurement_collection_t *collection);

static int write_text_file(const char *path, const char *data);
static int append_text_file(const char *path, const char *data);
static int write_labeled_block(const char *path, const char *label, const char *content);
static int write_kv_line(const char *path, const char *key, const char *value);

int measure_firmware(measurement_collection_t *collection, const char *bios_out_path);
int measure_kernel(measurement_collection_t *collection, const char *kernel_out_path);
int measure_sonic_config(measurement_collection_t *collection, const char *sonic_cfg_out_path);
int measure_routing(measurement_collection_t *collection, const char *routing_out_path);
int measure_services(measurement_collection_t *collection, const char *services_out_path);
int measure_hardware(measurement_collection_t *collection, const char *hw_out_path);

int save_measurements_json(measurement_collection_t *collection, const char *output_file);
int save_measurements_text(measurement_collection_t *collection, const char *output_file);
void print_usage(const char *program_name);
int parse_components(const char *component_str, int *components);

/* Initialize logging */
int init_logging(const char *log_path)
{
    if (log_path) {
        log_file = fopen(log_path, "a");
        if (!log_file)
        {
            fprintf(stderr, "Failed to open log file: %s - %s\n", log_path, strerror(errno));
            return -1;
        }
    } else {
        log_file = stderr; /* Default to stderr if no log file specified */
    }
    return 0;
}

/* Log message with timestamp */
void log_message(log_level_t level, const char *format, ...)
{
    if (level > current_log_level)
        return;

    const char *level_str[] = {"ERROR", "WARN", "INFO", "DEBUG"};
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char timestamp[32];

    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);

    FILE *output = log_file ? log_file : stderr;
    fprintf(output, "[%s] %s: ", timestamp, level_str[level]);

    va_list args;
    va_start(args, format);
    vfprintf(output, format, args);
    va_end(args);

    fprintf(output, "\n");
    if (log_file && log_file != stderr)
        fflush(log_file);
}

static int write_text_file(const char *path, const char *data)
{
    FILE *f = fopen(path, "w");
    if (!f)
    {
        log_message(LOG_ERROR, "open(%s) failed: %s", path, strerror(errno));
        return -1;
    }
    if (data && *data)
        fputs(data, f);
    fclose(f);
    return 0;
}

static int append_text_file(const char *path, const char *data)
{
    FILE *f = fopen(path, "a");
    if (!f)
    {
        log_message(LOG_ERROR, "open(%s) failed: %s", path, strerror(errno));
        return -1;
    }
    if (data && *data)
        fputs(data, f);
    fclose(f);
    return 0;
}

static int write_labeled_block(const char *path, const char *label, const char *content)
{
    if (!content || !*content)
        return 0;
    char hdr[256];
    snprintf(hdr, sizeof(hdr), "\n# ===== %s =====\n", label);
    if (append_text_file(path, hdr) != 0)
        return -1;
    return append_text_file(path, content);
}

/* small wrapper to build "<key>: <value>\n" lines */
static int write_kv_line(const char *path, const char *key, const char *value)
{
    char line[2048];
    snprintf(line, sizeof(line), "%s: %s\n", key, value ? value : "");
    return append_text_file(path, line);
}

/* Calculate SHA256 hash of file */
int hash_file(const char *filepath, char *hash_output)
{
    FILE *file;
    unsigned char buffer[8192];
    unsigned char hash[SHA256_DIGEST_SIZE];
    size_t bytes_read;
    EVP_MD_CTX *ctx;

    file = fopen(filepath, "rb");
    if (!file)
    {
        log_message(LOG_ERROR, "Cannot open file for hashing: %s", filepath);
        return -1;
    }

    ctx = EVP_MD_CTX_new();
    if (!ctx)
    {
        fclose(file);
        return -1;
    }

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1)
    {
        EVP_MD_CTX_free(ctx);
        fclose(file);
        return -1;
    }

    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0)
    {
        if (EVP_DigestUpdate(ctx, buffer, bytes_read) != 1)
        {
            EVP_MD_CTX_free(ctx);
            fclose(file);
            return -1;
        }
    }

    if (EVP_DigestFinal_ex(ctx, hash, NULL) != 1)
    {
        EVP_MD_CTX_free(ctx);
        fclose(file);
        return -1;
    }

    EVP_MD_CTX_free(ctx);
    fclose(file);

    /* Convert to hex string */
    for (int i = 0; i < SHA256_DIGEST_SIZE; i++)
    {
        sprintf(hash_output + (i * 2), "%02x", hash[i]);
    }
    hash_output[SHA256_HEX_SIZE - 1] = '\0';

    return 0;
}

/* Calculate SHA256 hash of string data */
int hash_string(const char *data, char *hash_output)
{
    unsigned char hash[SHA256_DIGEST_SIZE];
    EVP_MD_CTX *ctx;

    ctx = EVP_MD_CTX_new();
    if (!ctx)
        return -1;

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1 ||
        EVP_DigestUpdate(ctx, data, strlen(data)) != 1 ||
        EVP_DigestFinal_ex(ctx, hash, NULL) != 1)
    {
        EVP_MD_CTX_free(ctx);
        return -1;
    }

    EVP_MD_CTX_free(ctx);

    /* Convert to hex string */
    for (int i = 0; i < SHA256_DIGEST_SIZE; i++)
    {
        sprintf(hash_output + (i * 2), "%02x", hash[i]);
    }
    hash_output[SHA256_HEX_SIZE - 1] = '\0';

    return 0;
}

/* Read file content into buffer */
char *read_file_content(const char *filepath)
{
    FILE *file;
    char *content;
    long file_size;

    file = fopen(filepath, "r");
    if (!file)
    {
        log_message(LOG_ERROR, "Cannot read file: %s", filepath);
        return NULL;
    }

    fseek(file, 0, SEEK_END);
    file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    content = malloc(file_size + 1);
    if (!content)
    {
        fclose(file);
        return NULL;
    }

    fread(content, 1, file_size, file);
    content[file_size] = '\0';
    fclose(file);

    return content;
}

/* Execute command and capture output */
char *execute_command(const char *command)
{
    FILE *pipe;
    char *result;
    char buffer[4096];
    size_t total_size = 0;
    size_t buffer_size = 4096;

    pipe = popen(command, "r");
    if (!pipe)
    {
        log_message(LOG_ERROR, "Failed to execute command: %s", command);
        return NULL;
    }

    result = malloc(buffer_size);
    if (!result)
    {
        pclose(pipe);
        return NULL;
    }
    result[0] = '\0';

    while (fgets(buffer, sizeof(buffer), pipe) != NULL)
    {
        size_t buffer_len = strlen(buffer);
        if (total_size + buffer_len >= buffer_size)
        {
            buffer_size *= 2;
            result = realloc(result, buffer_size);
            if (!result)
            {
                pclose(pipe);
                return NULL;
            }
        }
        strcat(result, buffer);
        total_size += buffer_len;
    }

    pclose(pipe);
    return result;
}

/* Initialize measurement collection */
measurement_collection_t *init_measurements(void)
{
    measurement_collection_t *collection;

    collection = malloc(sizeof(measurement_collection_t));
    if (!collection)
        return NULL;

    collection->capacity = 64;
    collection->count = 0;
    collection->measurements = malloc(sizeof(measurement_t) * collection->capacity);

    if (!collection->measurements)
    {
        free(collection);
        return NULL;
    }

    return collection;
}

/* Add measurement to collection */
int add_measurement(measurement_collection_t *collection, const char *component,
                    const char *subcomponent, const char *hash, const char *description)
{
    if (collection->count >= collection->capacity)
    {
        collection->capacity *= 2;
        collection->measurements = realloc(collection->measurements,
                                           sizeof(measurement_t) * collection->capacity);
        if (!collection->measurements)
            return -1;
    }

    measurement_t *m = &collection->measurements[collection->count];
    strncpy(m->component, component, sizeof(m->component) - 1);
    m->component[sizeof(m->component) - 1] = '\0';
    strncpy(m->subcomponent, subcomponent, sizeof(m->subcomponent) - 1);
    m->subcomponent[sizeof(m->subcomponent) - 1] = '\0';
    strncpy(m->hash, hash, sizeof(m->hash) - 1);
    m->hash[sizeof(m->hash) - 1] = '\0';
    strncpy(m->description, description, sizeof(m->description) - 1);
    m->description[sizeof(m->description) - 1] = '\0';
    m->timestamp = time(NULL);

    collection->count++;
    log_message(LOG_INFO, "Added measurement: %s:%s -> %s", component, subcomponent, hash);

    return 0;
}

int measure_firmware(measurement_collection_t *collection, const char *bios_out_path) {
    char hash[SHA256_HEX_SIZE];
    char *content;

    log_message(LOG_INFO, "Measuring firmware/BIOS...");

    content = read_file_content("/sys/class/dmi/id/bios_vendor");
    if (content) {
        /* Remove newlines for cleaner output */
        char *newline = strchr(content, '\n');
        if (newline) *newline = '\0';
        
        write_kv_line(bios_out_path, "bios_vendor", content);
        if (hash_string(content, hash) == 0)
            add_measurement(collection, "firmware", "bios_vendor", hash, content);
        free(content);
    }

    content = read_file_content("/sys/class/dmi/id/bios_version");
    if (content) {
        char *newline = strchr(content, '\n');
        if (newline) *newline = '\0';
        
        write_kv_line(bios_out_path, "bios_version", content);
        if (hash_string(content, hash) == 0)
            add_measurement(collection, "firmware", "bios_version", hash, content);
        free(content);
    }

    content = read_file_content("/sys/class/dmi/id/bios_date");
    if (content) {
        char *newline = strchr(content, '\n');
        if (newline) *newline = '\0';
        
        write_kv_line(bios_out_path, "bios_date", content);
        if (hash_string(content, hash) == 0)
            add_measurement(collection, "firmware", "bios_date", hash, content);
        free(content);
    }
    return 0;
}

int measure_kernel(measurement_collection_t *collection, const char *kernel_out_path) {
    char hash[SHA256_HEX_SIZE];
    char *content;
    struct utsname uts;

    log_message(LOG_INFO, "Measuring kernel...");

    if (uname(&uts) == 0) {
        char kernel_info[512];
        snprintf(kernel_info, sizeof(kernel_info), "%s %s %s", uts.sysname, uts.release, uts.version);
        write_kv_line(kernel_out_path, "uname", kernel_info);
        if (hash_string(kernel_info, hash) == 0)
            add_measurement(collection, "kernel", "version", hash, uts.release);
    }

    content = read_file_content("/proc/cmdline");
    if (content) {
        write_labeled_block(kernel_out_path, "/proc/cmdline", content);
        if (hash_string(content, hash) == 0)
            add_measurement(collection, "kernel", "cmdline", hash, "boot_parameters");
        free(content);
    }

    content = execute_command("lsmod | sort");
    if (content) {
        write_labeled_block(kernel_out_path, "lsmod", content);
        if (hash_string(content, hash) == 0)
            add_measurement(collection, "kernel", "modules", hash, "loaded_modules");
        free(content);
    }

    if (access("/proc/config.gz", R_OK) == 0) {
        content = execute_command("zcat /proc/config.gz");
        if (content) {
            write_labeled_block(kernel_out_path, "/proc/config.gz", content);
            if (hash_string(content, hash) == 0)
                add_measurement(collection, "kernel", "config", hash, "kernel_config");
            free(content);
        }
    }
    return 0;
}

int measure_sonic_config(measurement_collection_t *collection, const char *sonic_cfg_out_path) {
    char hash[SHA256_HEX_SIZE];
    const char *sonic_files[] = {
        "/etc/sonic/config_db.json",
        "/etc/sonic/sonic_version.yml",
        "/etc/sonic/frr/frr.conf",
        "/etc/sonic/teamd.conf",
        NULL
    };
    log_message(LOG_INFO, "Measuring SONiC configuration...");

    for (int i = 0; sonic_files[i]; i++) {
        if (access(sonic_files[i], R_OK) == 0) {
            if (hash_file(sonic_files[i], hash) == 0) {
                const char *bn = strrchr(sonic_files[i], '/'); bn = bn ? bn+1 : sonic_files[i];
                char line[2048]; snprintf(line, sizeof(line), "%s  %s\n", hash, bn);
                append_text_file(sonic_cfg_out_path, line);
                add_measurement(collection, "sonic", "config", hash, bn);
            }
        }
    }

    DIR *dir = opendir("/etc/sonic");
    if (dir) {
        struct dirent *entry;
        char filepath[MAX_PATH];
        while ((entry = readdir(dir)) != NULL) {
            if (entry->d_type == DT_REG &&
               (strstr(entry->d_name, ".json") || strstr(entry->d_name, ".yml"))) {
                snprintf(filepath, sizeof(filepath), "/etc/sonic/%s", entry->d_name);
                if (hash_file(filepath, hash) == 0) {
                    char line[2048]; snprintf(line, sizeof(line), "%s  %s\n", hash, entry->d_name);
                    append_text_file(sonic_cfg_out_path, line);
                    add_measurement(collection, "sonic", "config", hash, entry->d_name);
                }
            }
        }
        closedir(dir);
    }
    return 0;
}

/* Measure routing and forwarding configuration (stable parts only) */
int measure_routing(measurement_collection_t *collection, const char *routing_out_path) {
    char hash[SHA256_HEX_SIZE];
    char *content;

    log_message(LOG_INFO, "Measuring routing configuration...");

    content = execute_command("ip route show | sed 's/expires [0-9]*sec//g' | sort");
    if (content) {
        write_labeled_block(routing_out_path, "IPv4 routes (normalized)", content);
        if (hash_string(content, hash) == 0)
            add_measurement(collection, "routing", "static_routes", hash, "static_ip_routes");
        free(content);
    }

    content = execute_command("ip -6 route show | sed 's/expires [0-9]*sec//g' | sort");
    if (content) {
        write_labeled_block(routing_out_path, "IPv6 routes (normalized)", content);
        if (hash_string(content, hash) == 0)
            add_measurement(collection, "routing", "static_ipv6_routes", hash, "static_ipv6_routes");
        free(content);
    }

    content = execute_command("ip addr show | grep -E '^[0-9]+:|inet ' | sed 's/valid_lft [0-9]*sec//g' | sed 's/preferred_lft [0-9]*sec//g' | sort");
    if (content) {
        write_labeled_block(routing_out_path, "Interface addresses (normalized)", content);
        if (hash_string(content, hash) == 0)
            add_measurement(collection, "routing", "interface_config", hash, "interface_addresses");
        free(content);
    }

    /* FRR running config, no comments/blank lines */
    content = execute_command("vtysh -c 'show running-config' 2>/dev/null | grep -v '^!' | sed '/^$/d'");
    if (content && strlen(content) > 0) {
        write_labeled_block(routing_out_path, "FRR running-config (filtered)", content);
        if (hash_string(content, hash) == 0)
            add_measurement(collection, "routing", "frr_config", hash, "frr_running_config");
        free(content);
    }

    /* BGP table sample (stable subset) */
    content = execute_command("vtysh -c 'show ip bgp' 2>/dev/null | grep -E '^(\\*|>)' | awk '{print $1,$2,$3}' | sort");
    if (content && strlen(content) > 0) {
        write_labeled_block(routing_out_path, "BGP best/valid (subset)", content);
        if (hash_string(content, hash) == 0)
            add_measurement(collection, "routing", "bgp_routes", hash, "bgp_route_table");
        free(content);
    }
    return 0;
}

/* Measure Docker containers and services */
int measure_services(measurement_collection_t *collection, const char *services_out_path) {
    char hash[SHA256_HEX_SIZE];
    char *content;
    char command[512];

    log_message(LOG_INFO, "Measuring services and containers...");

    content = execute_command("docker ps --format '{{.Names}}:{{.Image}}:{{.Status}}' | sort");
    if (content) {
        write_labeled_block(services_out_path, "docker ps", content);
        if (hash_string(content, hash) == 0)
            add_measurement(collection, "service", "containers", hash, "running_containers");
        free(content);
    }

    content = execute_command("docker images --format '{{.Repository}}:{{.Tag}}:{{.ID}}' | sort");
    if (content) {
        write_labeled_block(services_out_path, "docker images", content);
        if (hash_string(content, hash) == 0)
            add_measurement(collection, "service", "images", hash, "docker_images");
        free(content);
    }

    const char *sonic_containers[] = {"swss","syncd","bgp","teamd","lldp","snmp","dhcp_relay",NULL};
    for (int i = 0; sonic_containers[i]; i++) {
        snprintf(command, sizeof(command),
                 "docker inspect %s --format='{{.Id}}:{{.Config.Image}}:{{.State.Status}}' 2>/dev/null",
                 sonic_containers[i]);
        content = execute_command(command);
        if (content && strlen(content) > 10) {
            char lbl[128]; snprintf(lbl, sizeof(lbl), "docker inspect %s", sonic_containers[i]);
            write_labeled_block(services_out_path, lbl, content);
            if (hash_string(content, hash) == 0)
                add_measurement(collection, "service", sonic_containers[i], hash, sonic_containers[i]);
        }
        if (content) free(content);
    }

    content = execute_command("docker exec redis redis-cli --raw keys '*' 2>/dev/null | sort");
    if (content && *content) {
        write_labeled_block(services_out_path, "redis keys (sorted)", content);
        /* optional values snapshot could be too heavy; keep hashed only if you do it */
        if (hash_string(content, hash) == 0)
            add_measurement(collection, "service", "redis_state", hash, "redis_keys");
        free(content);
    }

    content = execute_command("systemctl list-units --type=service --state=active --no-pager --no-legend | awk '{print $1}' | sort");
    if (content) {
        write_labeled_block(services_out_path, "systemd active services", content);
        if (hash_string(content, hash) == 0)
            add_measurement(collection, "service", "systemd", hash, "active_services");
        free(content);
    }
    return 0;
}

/* Measure hardware information */
int measure_hardware(measurement_collection_t *collection, const char *hw_out_path) {
    char hash[SHA256_HEX_SIZE];
    char *content;

    log_message(LOG_INFO, "Measuring hardware information...");

    content = read_file_content("/proc/cpuinfo");
    if (content) {
        write_labeled_block(hw_out_path, "/proc/cpuinfo", content);
        if (hash_string(content, hash) == 0)
            add_measurement(collection, "hardware", "cpu", hash, "cpu_info");
        free(content);
    }
  
    content = execute_command("ip link show | grep -E '^[0-9]+:' | sort");
    if (content) {
        write_labeled_block(hw_out_path, "ip link (names)", content);
        if (hash_string(content, hash) == 0)
            add_measurement(collection, "hardware", "interfaces", hash, "network_interfaces");
        free(content);
    }
    return 0;
}

/* Save measurements to JSON file */
int save_measurements_json(measurement_collection_t *collection, const char *output_file)
{
    json_object *root, *measurements_array, *measurement_obj;
    json_object *component_obj, *subcomponent_obj, *hash_obj, *desc_obj, *timestamp_obj;
    FILE *file;

    log_message(LOG_INFO, "Saving measurements to JSON: %s", output_file);

    root = json_object_new_object();
    measurements_array = json_object_new_array();

    json_object_object_add(root, "timestamp", json_object_new_int64(time(NULL)));
    json_object_object_add(root, "measurement_count", json_object_new_int(collection->count));
    json_object_object_add(root, "measurements", measurements_array);

    for (size_t i = 0; i < collection->count; i++)
    {
        measurement_t *m = &collection->measurements[i];

        measurement_obj = json_object_new_object();
        component_obj = json_object_new_string(m->component);
        subcomponent_obj = json_object_new_string(m->subcomponent);
        hash_obj = json_object_new_string(m->hash);
        desc_obj = json_object_new_string(m->description);
        timestamp_obj = json_object_new_int64(m->timestamp);

        json_object_object_add(measurement_obj, "component", component_obj);
        json_object_object_add(measurement_obj, "subcomponent", subcomponent_obj);
        json_object_object_add(measurement_obj, "hash", hash_obj);
        json_object_object_add(measurement_obj, "description", desc_obj);
        json_object_object_add(measurement_obj, "timestamp", timestamp_obj);

        json_object_array_add(measurements_array, measurement_obj);
    }

    file = fopen(output_file, "w");
    if (!file)
    {
        log_message(LOG_ERROR, "Failed to open output file: %s", output_file);
        json_object_put(root);
        return -1;
    }

    fprintf(file, "%s\n", json_object_to_json_string_ext(root, JSON_C_TO_STRING_PRETTY));
    fclose(file);
    json_object_put(root);

    log_message(LOG_INFO, "Saved %zu measurements to %s", collection->count, output_file);
    return 0;
}

/* Save measurements to text file (compatible with bash scripts) */
int save_measurements_text(measurement_collection_t *collection, const char *output_file)
{
    FILE *file;

    log_message(LOG_INFO, "Saving measurements to text: %s", output_file);

    file = fopen(output_file, "w");
    if (!file)
    {
        log_message(LOG_ERROR, "Failed to open output file: %s", output_file);
        return -1;
    }

    for (size_t i = 0; i < collection->count; i++)
    {
        measurement_t *m = &collection->measurements[i];
        fprintf(file, "%s:%s:%s\n", m->component, m->subcomponent, m->hash);
    }

    fclose(file);
    log_message(LOG_INFO, "Saved %zu measurements to %s", collection->count, output_file);
    return 0;
}

/* Free measurement collection */
void free_measurements(measurement_collection_t *collection)
{
    if (collection)
    {
        if (collection->measurements)
        {
            free(collection->measurements);
        }
        free(collection);
    }
}

/* Print usage information */
void print_usage(const char *program_name)
{
    printf("SONiC Attestation System - C Measurement Collector\n\n");
    printf("Usage: %s [options]\n\n", program_name);
    printf("Options:\n");
    printf("  -o, --output <file>     Output file path (default: measurements.txt)\n");
    printf("  -j, --json <file>       JSON output file path\n");
    printf("  -l, --log <file>        Log file path (default: stderr)\n");
    printf("  -v, --verbose           Enable verbose logging\n");
    printf("  -q, --quiet             Quiet mode (errors only)\n");
    printf("  -c, --components <list> Comma-separated list of components to measure\n");
    printf("                          (firmware,kernel,sonic,routing,services,hardware)\n");
    printf("  --dir <directory>       Output directory for component files\n");
    printf("  -h, --help              Show this help message\n\n");
    printf("Examples:\n");
    printf("  %s -o /tmp/measurements.txt -j /tmp/measurements.json\n", program_name);
    printf("  %s -c firmware,kernel,sonic -v\n", program_name);
    printf("  %s --quiet --output /var/lib/sonic/measurements.txt\n", program_name);
}

/* Parse component list */
int parse_components(const char *component_str, int *components)
{
    char *str_copy, *token;
    int count = 0;

    /* Initialize all components to disabled */
    for (int i = 0; i < 6; i++)
        components[i] = 0;

    str_copy = strdup(component_str);
    if (!str_copy)
        return -1;

    token = strtok(str_copy, ",");
    while (token != NULL && count < 6)
    {
        if (strcmp(token, "firmware") == 0)
            components[0] = 1;
        else if (strcmp(token, "kernel") == 0)
            components[1] = 1;
        else if (strcmp(token, "sonic") == 0)
            components[2] = 1;
        else if (strcmp(token, "routing") == 0)
            components[3] = 1;
        else if (strcmp(token, "services") == 0)
            components[4] = 1;
        else if (strcmp(token, "hardware") == 0)
            components[5] = 1;
        else
        {
            log_message(LOG_WARN, "Unknown component: %s", token);
        }
        token = strtok(NULL, ",");
        count++;
    }

    free(str_copy);
    return count;
}

/* Create directory if it doesn't exist */
int create_directory(const char *dir_path)
{
    struct stat st = {0};
    
    if (stat(dir_path, &st) == -1) {
        if (mkdir(dir_path, 0755) == -1) {
            log_message(LOG_ERROR, "Failed to create directory %s: %s", dir_path, strerror(errno));
            return -1;
        }
        log_message(LOG_INFO, "Created directory: %s", dir_path);
    }
    return 0;
}

/* Main function */
int main(int argc, char *argv[])
{
    measurement_collection_t *collection;
    char *output_file = "measurements.txt";
    char *json_file = NULL;
    char *out_dir = NULL;
    char *log_path = NULL;
    // Default: measure only static components (excluding routing and services which can be dynamic)
    int components[6] = {1, 1, 1, 0, 0, 1}; // firmware, kernel, sonic, routing, services, hardware
    int ret_code = 0;

    /* Parse command line arguments */
    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0)
        {
            print_usage(argv[0]);
            return 0;
        }
        else if (strcmp(argv[i], "-o") == 0 || strcmp(argv[i], "--output") == 0)
        {
            if (i + 1 < argc)
                output_file = argv[++i];
            else
            {
                fprintf(stderr, "Error: %s requires an argument\n", argv[i]);
                return 1;
            }
        }
        else if (strcmp(argv[i], "-j") == 0 || strcmp(argv[i], "--json") == 0)
        {
            if (i + 1 < argc)
                json_file = argv[++i];
            else
            {
                fprintf(stderr, "Error: %s requires an argument\n", argv[i]);
                return 1;
            }
        }
        else if (strcmp(argv[i], "-l") == 0 || strcmp(argv[i], "--log") == 0)
        {
            if (i + 1 < argc)
                log_path = argv[++i];
            else
            {
                fprintf(stderr, "Error: %s requires an argument\n", argv[i]);
                return 1;
            }
        }
        else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0)
        {
            current_log_level = LOG_DEBUG;
        }
        else if (strcmp(argv[i], "-q") == 0 || strcmp(argv[i], "--quiet") == 0)
        {
            current_log_level = LOG_ERROR;
        }
        else if (strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--components") == 0)
        {
            if (i + 1 < argc)
            {
                if (parse_components(argv[++i], components) < 0)
                {
                    fprintf(stderr, "Error: Failed to parse components list\n");
                    return 1;
                }
            }
            else
            {
                fprintf(stderr, "Error: %s requires an argument\n", argv[i]);
                return 1;
            }
        }
        else if (strcmp(argv[i], "--dir") == 0)
        {
            if (i + 1 < argc)
                out_dir = argv[++i];
            else
            {
                fprintf(stderr, "Error: %s requires an argument\n", argv[i]);
                return 1;
            }
        }
        else
        {
            fprintf(stderr, "Error: Unknown option %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    /* Initialize logging first - this is critical for LOG_INFO to work */
    if (init_logging(log_path) != 0)
    {
        fprintf(stderr, "Failed to initialize logging\n");
        return 1;
    }

    log_message(LOG_INFO, "SONiC Measurement Collector starting...");

    /* Determine output directory */
    char out_dir_buf[MAX_PATH] = ".";
    if (!out_dir)
    {
        /* Default: directory of the -o output file, else "." */
        const char *slash = strrchr(output_file, '/');
        if (slash)
        {
            size_t len = (size_t)(slash - output_file);
            if (len >= sizeof(out_dir_buf))
                len = sizeof(out_dir_buf) - 1;
            memcpy(out_dir_buf, output_file, len);
            out_dir_buf[len] = '\0';
            out_dir = out_dir_buf;
        }
        else
        {
            out_dir = ".";
        }
    }

    /* Create output directory if needed */
    if (create_directory(out_dir) != 0)
    {
        ret_code = 1;
        goto cleanup;
    }

    /* Build per-class file paths */
    char bios_path[MAX_PATH], kernel_path[MAX_PATH], routing_path[MAX_PATH],
         hw_path[MAX_PATH], services_path[MAX_PATH], sonic_cfg_path[MAX_PATH];

    snprintf(bios_path, sizeof(bios_path), "%s/bios.txt", out_dir);
    snprintf(kernel_path, sizeof(kernel_path), "%s/kernel.txt", out_dir);
    snprintf(routing_path, sizeof(routing_path), "%s/routing.txt", out_dir);
    snprintf(hw_path, sizeof(hw_path), "%s/hardware.txt", out_dir);
    snprintf(services_path, sizeof(services_path), "%s/services.txt", out_dir);
    snprintf(sonic_cfg_path, sizeof(sonic_cfg_path), "%s/sonic_config.txt", out_dir);

    /* Start each file clean */
    if (write_text_file(bios_path, "") != 0 ||
        write_text_file(kernel_path, "") != 0 ||
        write_text_file(routing_path, "") != 0 ||
        write_text_file(hw_path, "") != 0 ||
        write_text_file(services_path, "") != 0 ||
        write_text_file(sonic_cfg_path, "") != 0)
    {
        log_message(LOG_ERROR, "Failed to initialize output files");
        ret_code = 1;
        goto cleanup;
    }

    /* Initialize measurement collection */
    collection = init_measurements();
    if (!collection)
    {
        log_message(LOG_ERROR, "Failed to initialize measurement collection");
        ret_code = 1;
        goto cleanup;
    }

    log_message(LOG_INFO, "Initialized measurement collection successfully");

    /* Perform measurements based on enabled components */
    if (components[0])
    {
        if (measure_firmware(collection, bios_path) != 0)
        {
            log_message(LOG_WARN, "Firmware measurement failed");
        }
    }

    if (components[1])
    {
        if (measure_kernel(collection, kernel_path) != 0)
        {
            log_message(LOG_WARN, "Kernel measurement failed");
        }
    }

    if (components[2])
    {
        if (measure_sonic_config(collection, sonic_cfg_path) != 0)
        {
            log_message(LOG_WARN, "SONiC configuration measurement failed");
        }
    }

    if (components[3])
    {
        if (measure_routing(collection, routing_path) != 0)
        {
            log_message(LOG_WARN, "Routing measurement failed");
        }
    }

    if (components[4])
    {
        if (measure_services(collection, services_path) != 0)
        {
            log_message(LOG_WARN, "Services measurement failed");
        }
    }

    if (components[5])
    {
        if (measure_hardware(collection, hw_path) != 0)
        {
            log_message(LOG_WARN, "Hardware measurement failed");
        }
    }

    /* Save measurements */
    if (save_measurements_text(collection, output_file) != 0)
    {
        log_message(LOG_ERROR, "Failed to save text measurements");
        ret_code = 1;
        goto cleanup_collection;
    }

    if (json_file && save_measurements_json(collection, json_file) != 0)
    {
        log_message(LOG_ERROR, "Failed to save JSON measurements");
        ret_code = 1;
        goto cleanup_collection;
    }

    log_message(LOG_INFO, "Measurement collection completed successfully");
    log_message(LOG_INFO, "Total measurements: %zu", collection->count);

cleanup_collection:
    /* Cleanup measurement collection */
    free_measurements(collection);

cleanup:
    /* Cleanup logging */
    if (log_file && log_file != stderr)
        fclose(log_file);

    return ret_code;
}