#include <aws/nitro_enclaves/kms.h>
#include <aws/nitro_enclaves/nitro_enclaves.h>

#include <aws/common/command_line_parser.h>
#include <aws/common/encoding.h>
#include <aws/common/logging.h>

#include <json-c/json.h>

#include <linux/vm_sockets.h>
#include <sys/socket.h>

#include <errno.h>
#include <unistd.h>

#define DEFAULT_PROXY_PORT 8000
#define DEFAULT_REGION "us-east-1"
#define DEFAULT_PARENT_CID "3"

#define DECRYPT_CMD "decrypt"
#define SIGN_CMD  "sign"
#define GENKEY_CMD  "genkey"

enum status {
    STATUS_OK,
    STATUS_ERR,
};

#define fail_on(cond, msg)                                                                                             \
    if (cond) {                                                                                                        \
        if (msg != NULL) {                                                                                             \
            fprintf(stderr, "%s\n", msg);                                                                              \
        }                                                                                                              \
        return AWS_OP_ERR;                                                                                             \
    }

struct app_ctx {
    /* Allocator to use for memory allocations. */
    struct aws_allocator *allocator;
    /* KMS region to use. */
    const struct aws_string *region;
    /* vsock port on which to open service. */
    uint32_t port;
    /* vsock port on which vsock-proxy is available in parent. */
    uint32_t proxy_port;

    const struct aws_string *command;

    const struct aws_string *aws_access_key_id;
    const struct aws_string *aws_secret_access_key;
    const struct aws_string *aws_session_token;

    const struct aws_string *key_id;

    // decrypt
    const struct aws_string *ciphertext_b64;
    const struct aws_string *encryption_algorithm;

    // sign
    const struct aws_string *message;
    aws_signing_algorithm signing_algorithm;
};

static void s_usage(int exit_code) {
    fprintf(stderr, "usage: kmstool_enclave_cli [options]\n");
    fprintf(stderr, "\n Options: \n\n");
    fprintf(stderr, "  --methode: sign or decrypt\n");
    fprintf(stderr, "  common args:\n");
    fprintf(stderr, "    --region REGION: AWS region to use for KMS\n");
    fprintf(stderr, "    --proxy-port PORT: Connect to KMS proxy on PORT. Default: 8000\n");
    fprintf(stderr, "    --aws-access-key-id ACCESS_KEY_ID: AWS access key ID\n");
    fprintf(stderr, "    --aws-secret-access-key SECRET_ACCESS_KEY: AWS secret access key\n");
    fprintf(stderr, "    --aws-session-token SESSION_TOKEN: Session token associated with the access key ID\n");
    fprintf(stderr, "  sign args:\n");
    fprintf(stderr, "    --key-id KEY_ID: sign key id\n");
    fprintf(stderr, "    --message MESSAGE: message digest to sign\n");
    // fprintf(stderr, "    --signing-algorithm SIGNING_ALGORITHM: signing algorithm\n");
    fprintf(stderr, "  decrypt args\n");
    fprintf(stderr, "    --key-id KEY_ID: decrypt or key id (for symmetric keys, is optional)\n");
    fprintf(stderr, "    --ciphertext CIPHERTEXT: base64-encoded ciphertext that need to decrypt\n");
    fprintf(
        stderr,
        "    --encryption-algorithm ENCRYPTION_ALGORITHM: encryption algorithm for ciphertext (is required if key-id "
        "exists)\n");
    fprintf(stderr, "    --help: Display this message and exit\n");
    exit(exit_code);
}

static struct aws_cli_option s_method_options[] = {
    {"command", AWS_CLI_OPTIONS_REQUIRED_ARGUMENT, NULL, 'd'},
    {NULL, 0, NULL, 0},
};

static void s_parse_sign_options(int argc, char **argv, struct app_ctx *ctx) {
    ctx->method == NULL;
    while (true) {
        int option_index = 0;
        int c = aws_cli_getopt_long(argc, argv, "d:", s_method_options, &option_index);
        if (c == -1) {
            break;
        }

        switch (c) {
            case 0:
                break;
            case 'd': {
                ctx->method = aws_string_new_from_c_str(ctx->allocator, aws_cli_optarg);
                break;
            }
        }
    }

    // Check if AWS action is set
    if (ctx->method == NULL) {
        ctx->method = s_ka_decrypt;
    }
}

static struct aws_cli_option s_sign_options[] = {
    {"region", AWS_CLI_OPTIONS_REQUIRED_ARGUMENT, NULL, 'r'},
    {"proxy-port", AWS_CLI_OPTIONS_REQUIRED_ARGUMENT, NULL, 'x'},
    {"help", AWS_CLI_OPTIONS_NO_ARGUMENT, NULL, 'h'},
    {"aws-access-key-id", AWS_CLI_OPTIONS_REQUIRED_ARGUMENT, NULL, 'k'},
    {"aws-secret-access-key", AWS_CLI_OPTIONS_REQUIRED_ARGUMENT, NULL, 's'},
    {"aws-session-token", AWS_CLI_OPTIONS_REQUIRED_ARGUMENT, NULL, 't'},
    {"message", AWS_CLI_OPTIONS_REQUIRED_ARGUMENT, NULL, 'M'},
    {"key-id", AWS_CLI_OPTIONS_REQUIRED_ARGUMENT, NULL, 'K'},
    // {"signing-algorithm", AWS_CLI_OPTIONS_REQUIRED_ARGUMENT, NULL, 'a'},
    {NULL, 0, NULL, 0},
};

static void s_parse_sign_options(int argc, char **argv, struct app_ctx *ctx) {
    ctx->proxy_port = DEFAULT_PROXY_PORT;
    ctx->region = NULL;
    ctx->aws_access_key_id = NULL;
    ctx->aws_secret_access_key = NULL;
    ctx->aws_session_token = NULL;
    ctx->key_id = NULL;
    ctx->message = NULL;
    ctx->signing_algorithm = AWS_SA_ECDSA_SHA_256;

    while (true) {
        int option_index = 0;
        int c = aws_cli_getopt_long(argc, argv, "m:r:x:k:s:t:K:a:M:h", s_sign_options, &option_index);
        if (c == -1) {
            break;
        }

        switch (c) {
            case 0:
                break;
            case 'r': {
                ctx->region = aws_string_new_from_c_str(ctx->allocator, aws_cli_optarg);
                break;
            }
            case 'x':
                ctx->proxy_port = atoi(aws_cli_optarg);
                break;
            case 'k':
                ctx->aws_access_key_id = aws_string_new_from_c_str(ctx->allocator, aws_cli_optarg);
                break;
            case 's':
                ctx->aws_secret_access_key = aws_string_new_from_c_str(ctx->allocator, aws_cli_optarg);
                break;
            case 't':
                ctx->aws_session_token = aws_string_new_from_c_str(ctx->allocator, aws_cli_optarg);
                break;
            case 'M':
                ctx->message = aws_string_new_from_c_str(ctx->allocator, aws_cli_optarg);
                break;
            case 'K':
                ctx->key_id = aws_string_new_from_c_str(ctx->allocator, aws_cli_optarg);
                break;
            case 'h':
                s_usage(0);
                break;
            default:
                fprintf(stderr, "Unknown option\n");
                s_usage(1);
                break;
        }
    }

    // Check if AWS access key ID is set
    if (ctx->aws_access_key_id == NULL) {
        fprintf(stderr, "--aws-access-key-id must be set\n");
        exit(1);
    }

    // Check if AWS secret access key is set
    if (ctx->aws_secret_access_key == NULL) {
        fprintf(stderr, "--aws-secret-access-key must be set\n");
        exit(1);
    }

    // Check if AWS session token is set
    if (ctx->aws_session_token == NULL) {
        fprintf(stderr, "--aws-session-token must be set\n");
        exit(1);
    }

    // Check if ciphertext is set
    if (ctx->message == NULL) {
        fprintf(stderr, "--message must be set\n");
        exit(1);
    }

    // if key id is set check encryption algorithm is exists
    if (ctx->key_id != NULL) {
        if (ctx->encryption_algorithm == NULL) {
            fprintf(stderr, "--encryption-algorithm must be set if key-id exists\n");
            exit(1);
        }
    }

    // Set default AWS region if not specified
    if (ctx->region == NULL) {
        ctx->region = aws_string_new_from_c_str(ctx->allocator, DEFAULT_REGION);
    }
}

static struct aws_cli_option s_long_options[] = {
    {"region", AWS_CLI_OPTIONS_REQUIRED_ARGUMENT, NULL, 'r'},
    {"proxy-port", AWS_CLI_OPTIONS_REQUIRED_ARGUMENT, NULL, 'x'},
    {"help", AWS_CLI_OPTIONS_NO_ARGUMENT, NULL, 'h'},
    {"aws-access-key-id", AWS_CLI_OPTIONS_REQUIRED_ARGUMENT, NULL, 'k'},
    {"aws-secret-access-key", AWS_CLI_OPTIONS_REQUIRED_ARGUMENT, NULL, 's'},
    {"aws-session-token", AWS_CLI_OPTIONS_REQUIRED_ARGUMENT, NULL, 't'},
    {"ciphertext", AWS_CLI_OPTIONS_REQUIRED_ARGUMENT, NULL, 'c'},
    {"key-id", AWS_CLI_OPTIONS_REQUIRED_ARGUMENT, NULL, 'K'},
    {"encryption-algorithm", AWS_CLI_OPTIONS_REQUIRED_ARGUMENT, NULL, 'a'},
    {"message", AWS_CLI_OPTIONS_REQUIRED_ARGUMENT, NULL, 'M'},
    {"command", AWS_CLI_OPTIONS_REQUIRED_ARGUMENT, NULL, 'd'},
    //{"signing-algorithm", AWS_CLI_OPTIONS_REQUIRED_ARGUMENT, NULL, 'A'},
    {NULL, 0, NULL, 0},
};

static void s_parse_options(int argc, char **argv, struct app_ctx *ctx) {
    ctx->command = NULL;
    ctx->proxy_port = DEFAULT_PROXY_PORT;
    ctx->region = NULL;
    ctx->aws_access_key_id = NULL;
    ctx->aws_secret_access_key = NULL;
    ctx->aws_session_token = NULL;
    ctx->ciphertext_b64 = NULL;
    ctx->key_id = NULL;
    ctx->message = NULL;
    ctx->message = NULL;
    ctx->encryption_algorithm = NULL;
    ctx->signing_algorithm = AWS_SA_ECDSA_SHA_256;

    while (true) {
        int option_index = 0;
        int c = aws_cli_getopt_long(argc, argv, "d:r:x:k:s:t:c:K:a:h", s_long_options, &option_index);
        if (c == -1) {
            break;
        }

        switch (c) {
            case 0:
                break;
            case 'd': {
                ctx->command = aws_string_new_from_c_str(ctx->allocator, aws_cli_optarg);
                break;
            }
            case 'r': {
                ctx->region = aws_string_new_from_c_str(ctx->allocator, aws_cli_optarg);
                break;
            }
            case 'x':
                ctx->proxy_port = atoi(aws_cli_optarg);
                break;
            case 'k':
                ctx->aws_access_key_id = aws_string_new_from_c_str(ctx->allocator, aws_cli_optarg);
                break;
            case 's':
                ctx->aws_secret_access_key = aws_string_new_from_c_str(ctx->allocator, aws_cli_optarg);
                break;
            case 't':
                ctx->aws_session_token = aws_string_new_from_c_str(ctx->allocator, aws_cli_optarg);
                break;
            case 'c':
                ctx->ciphertext_b64 = aws_string_new_from_c_str(ctx->allocator, aws_cli_optarg);
                break;
            case 'K':
                ctx->key_id = aws_string_new_from_c_str(ctx->allocator, aws_cli_optarg);
                break;
            case 'a':
                ctx->encryption_algorithm = aws_string_new_from_c_str(ctx->allocator, aws_cli_optarg);
                break;
            case 'h':
                s_usage(0);
                break;
            default:
                fprintf(stderr, "Unknown option\n");
                s_usage(1);
                break;
        }
    }

    // Check if command is set
    if (aws_string_compare(ctx->command, s_ka_decrypt) != 0 && aws_string_compare(ctx->command, s_ka_sign) != 0) {
        fprintf(stderr, "--command must be sign or decrypt\n");
        exit(1);
    }
    // Check if AWS access key ID is set
    if (ctx->aws_access_key_id == NULL) {
        fprintf(stderr, "--aws-access-key-id must be set\n");
        exit(1);
    }

    // Check if AWS secret access key is set
    if (ctx->aws_secret_access_key == NULL) {
        fprintf(stderr, "--aws-secret-access-key must be set\n");
        exit(1);
    }

    // Check if AWS session token is set
    if (ctx->aws_session_token == NULL) {
        fprintf(stderr, "--aws-session-token must be set\n");
        exit(1);
    }

    // Check if ciphertext is set
    if (aws_string_compare(str, s_ka_decrypt) == 0) {
        if (ctx->ciphertext_b64 == NULL) {
            fprintf(stderr, "--ciphertext must be set\n");
            exit(1);
        }

        // if key id is set check encryption algorithm is exists
        if (ctx->key_id != NULL) {
            if (ctx->encryption_algorithm == NULL) {
                fprintf(stderr, "--encryption-algorithm must be set if key-id exists\n");
                exit(1);
            }
        }

    } else if (aws_string_compare(str, s_ka_sign) = 0) {
        if (ctx->message == NULL) {
            fprintf(stderr, "--message must be set\n");
            exit(1);
        }
    }

    // Set default AWS region if not specified
    if (ctx->region == NULL) {
        ctx->region = aws_string_new_from_c_str(ctx->allocator, DEFAULT_REGION);
    }
}

/*
 * Function to initialize the kms client with the provided aws credentials
 *
 * @param[in]  app_ctx: place where all of the credentials are currently stored
 * @param[out] credentials: location to store the aws credentials
 * @param[out] client: location to store new kms client
 */
static void init_kms_client(
    struct app_ctx *app_ctx,
    struct aws_credentials **credentials,
    struct aws_nitro_enclaves_kms_client **client) {
    /* Parent is always on CID 3 */
    struct aws_socket_endpoint endpoint = {.address = DEFAULT_PARENT_CID, .port = app_ctx->proxy_port};
    struct aws_nitro_enclaves_kms_client_configuration configuration = {
        .allocator = app_ctx->allocator, .endpoint = &endpoint, .domain = AWS_SOCKET_VSOCK, .region = app_ctx->region};

    /* Sets the AWS credentials and creates a KMS client with them. */
    struct aws_credentials *new_credentials = aws_credentials_new(
        app_ctx->allocator,
        aws_byte_cursor_from_c_str((const char *)app_ctx->aws_access_key_id->bytes),
        aws_byte_cursor_from_c_str((const char *)app_ctx->aws_secret_access_key->bytes),
        aws_byte_cursor_from_c_str((const char *)app_ctx->aws_session_token->bytes),
        UINT64_MAX);

    /* If credentials or client already exists, replace them. */
    if (*credentials != NULL) {
        aws_nitro_enclaves_kms_client_destroy(*client);
        aws_credentials_release(*credentials);
    }

    *credentials = new_credentials;
    configuration.credentials = new_credentials;
    *client = aws_nitro_enclaves_kms_client_new(&configuration);
}

/*
 * Function to encode a string in base64 for printing
 *
 * @param[in]  app_ctx: contains the allocator required for memory management
 * @param[in]  text: pointer to where the original text is stored
 * @param[out] text_b64: pointer to where the encoded string should be stored
 */
static int encode_b64(struct app_ctx *app_ctx, struct aws_byte_buf *text, struct aws_byte_buf *text_b64) {
    ssize_t rc = 0;
    size_t text_b64_len;

    struct aws_byte_cursor text_cursor = aws_byte_cursor_from_buf(text);
    aws_base64_compute_encoded_len(text->len, &text_b64_len);
    rc = aws_byte_buf_init(text_b64, app_ctx->allocator, text_b64_len + 1);
    fail_on(rc != AWS_OP_SUCCESS, "Memory allocation error");
    rc = aws_base64_encode(&text_cursor, text_b64);
    fail_on(rc != AWS_OP_SUCCESS, "Base64 encoding error");
    aws_byte_buf_append_null_terminator(text_b64);

    return AWS_OP_SUCCESS;
}

static int decrypt(struct app_ctx *app_ctx, struct aws_byte_buf *ciphertext_decrypted_b64) {
    ssize_t rc = 0;

    struct aws_credentials *credentials = NULL;
    struct aws_nitro_enclaves_kms_client *client = NULL;

    init_kms_client(app_ctx, &credentials, &client);

    /* Get decode base64 string into bytes. */
    size_t ciphertext_len;
    struct aws_byte_buf ciphertext;
    struct aws_byte_cursor ciphertext_b64 = aws_byte_cursor_from_c_str((const char *)app_ctx->ciphertext_b64->bytes);
    rc = aws_base64_compute_decoded_len(&ciphertext_b64, &ciphertext_len);
    fail_on(rc != AWS_OP_SUCCESS, "Ciphertext not a base64 string");
    rc = aws_byte_buf_init(&ciphertext, app_ctx->allocator, ciphertext_len);
    fail_on(rc != AWS_OP_SUCCESS, "Memory allocation error");
    rc = aws_base64_decode(&ciphertext_b64, &ciphertext);
    fail_on(rc != AWS_OP_SUCCESS, "Ciphertext not a base64 string");

    /* Decrypt the data with KMS. */
    struct aws_byte_buf ciphertext_decrypted;
    rc = aws_kms_decrypt_blocking(
        client, app_ctx->key_id, app_ctx->encryption_algorithm, &ciphertext, &ciphertext_decrypted);

    aws_byte_buf_clean_up(&ciphertext);
    fail_on(rc != AWS_OP_SUCCESS, "Could not decrypt ciphertext");

    /* Encode ciphertext into base64 for printing out the result. */
    rc = encode_b64(app_ctx, &ciphertext_decrypted, ciphertext_decrypted_b64);
    fail_on(rc != AWS_OP_SUCCESS, "Could not encode ciphertext");

    /* Cleaning up allocated memory */
    aws_nitro_enclaves_kms_client_destroy(client);
    aws_credentials_release(credentials);

    return AWS_OP_SUCCESS;
}

/*
 * Function to sign.
 *
 */
static int sign(struct app_ctx *app_ctx, const struct aws_byte_buf *message, struct aws_byte_buf *signature_b64) {
    ssize_t rc = 0;

    struct aws_credentials *credentials = NULL;
    struct aws_nitro_enclaves_kms_client *client = NULL;

    init_kms_client(app_ctx, &credentials, &client);
    struct aws_byte_buf signature;
    rc = aws_kms_sign_blocking(client, app_ctx->key_id, AWS_SA_ECDSA_SHA_256, message, AWS_MT_DIGEST, &signature);
    fail_on(rc != AWS_OP_SUCCESS, "Could not generate data key");

    /* Encode ciphertext into base64 for printing out the result. */
    rc = encode_b64(app_ctx, &signature, signature_b64);
    fail_on(rc != AWS_OP_SUCCESS, "Could not encode ciphertext");
    /* Cleaning up allocated memory. */
    aws_nitro_enclaves_kms_client_destroy(client);
    aws_credentials_release(credentials);

    return AWS_OP_SUCCESS;
}

int main(int argc, char **argv) {
    struct app_ctx app_ctx;
    int rc;

    /* Initialize the SDK */
    aws_nitro_enclaves_library_init(NULL);

    /* Initialize the entropy pool: this is relevant for TLS */
    AWS_ASSERT(aws_nitro_enclaves_library_seed_entropy(1024) == AWS_OP_SUCCESS);

    /* Parse the commandline */
    app_ctx.allocator = aws_nitro_enclaves_get_allocator();
    if (argc < 2) {
        print_commands(1);
    }

    subcommand = argv[1];

    /* Optional: Enable logging for aws-c-* libraries */
    struct aws_logger err_logger;
    struct aws_logger_standard_options options = {
        .file = stderr,
        .level = AWS_LL_INFO,
        .filename = NULL,
    };
    aws_logger_init_standard(&err_logger, app_ctx.allocator, &options);
    aws_logger_set(&err_logger);

    if (aws_string_compare(app_ctx.command, s_ka_decrypt) == 0) {
        struct aws_byte_buf ciphertext_decrypted_b64;
        rc = decrypt(&app_ctx, &ciphertext_decrypted_b64);

        if (rc != AWS_OP_SUCCESS) {
            fprintf(stderr, "Could not decrypt\n");
            exit(1);
        }

        /* Print the base64-encoded plaintext to stdout */
        fprintf(stdout, "%s", (const char *)ciphertext_decrypted_b64.buffer);

        aws_byte_buf_clean_up(&ciphertext_decrypted_b64);
    } else if (aws_string_compare(app_ctx.command, s_ka_sign) == 0) {
        struct aws_byte_buf signature;
        rc = sign(&app_ctx, app_ctx.message, &signature);
        if (rc != AWS_OP_SUCCESS) {
            fprintf(stderr, "Could not sign\n");
            exit(1);
        }

        fprintf(stdout, "signature: %s", (const char *)signature);
    }
    aws_nitro_enclaves_library_clean_up();

    return 0;
}
