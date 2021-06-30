#include <stdio.h>
#include <opencv2/imgcodecs.hpp>
#include "SslConnect.h"
#include "WindowsKeyStoreAdapter.h"
#include "NetworkTCP.h"
#include <windows.h>
#include <wincrypt.h>
#include <cryptuiapi.h>

#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "cryptui.lib")
#define CHK_NULL(x) if((x) == NULL) exit(1);
#define CHK_ERR(err, s) if((err) == -1) { perror(s); exit(1); }
#define CHK_SSL(err) if((err) == -1) { ERR_print_errors_fp(stderr); exit(2); }

static const char* PATH_CERT_FILE = "..\\..\\Certificates\\client.crt";
static const char* PATH_PRIVATE_KEY_FILE = "..\\..\\Certificates\\client.key";
static const char* PATH_ROOTCA_FILE = "..\\..\\Certificates\\rootca.crt";

static  int init_values[2] = { cv::IMWRITE_JPEG_QUALITY,80 };
static  std::vector<int> param(&init_values[0], &init_values[0] + 2);
static  std::vector<uchar> sendbuff;

SslConnect::SslConnect(bool _isServer) : isServer(_isServer), m_ctx(NULL), m_ssl(NULL) {
    method = (isServer) ? TLSv1_server_method() : TLSv1_client_method();
    SSL_library_init();
    OpenSSL_add_all_algorithms();        /* Load cryptos, et.al. */
    SSL_load_error_strings();            /* Bring in and register error messages */
}

SslConnect::~SslConnect() {
    if (m_ssl != NULL) {
        SSL_free(m_ssl);
        m_ssl = NULL;
    }
    if (m_ctx != NULL) {
        SSL_CTX_free(m_ctx);
        m_ctx = NULL;
    }
}

bool SslConnect::InitializeCtx()
{
    m_ctx = this->GetSslCtx();
    if (m_ctx == NULL) {
        return false;
    }
    if (!loadCertificatesFromWCS(m_ctx))
    {
        // Windows Certificate Store에 key가 없는 경우
        //std::cerr << "certification could not be found.\n";
        //return -1;
        // FIXME: 개발용으로 아래의 코드를 쓰지만, 테스트 버전에서는 삭제되어야 한다.
        printf("FIXME to use personal certificate!\n");
        this->LoadCertificates(PATH_CERT_FILE, PATH_PRIVATE_KEY_FILE);
    }
    return true;
}

bool SslConnect::Connect(int fd)
{
    m_ssl = SSL_new(m_ctx);
    SSL_set_fd(m_ssl, fd);
    if (SSL_connect(m_ssl) == -1) {
        printf("Connection failed\n");
        return false;
    }

    if (!this->VerifyCertificate()) {
        printf("Verification failed\n");
        return false;
    }

    return true;
}

/*---------------------------------------------------------------------*/
/*--- InitCTX - initialize the SSL engine.                          ---*/
/*---------------------------------------------------------------------*/
SSL_CTX* SslConnect::GetSslCtx(void)
{
    SSL_CTX* ctx;

    ctx = SSL_CTX_new(method);            /* Create new context */
    if (ctx == NULL)
    {
        printf("ctx Error\n");
    }
    return ctx;
}

/*---------------------------------------------------------------------*/
/*--- LoadCertificates - load from files.                           ---*/
/*---------------------------------------------------------------------*/
void SslConnect::LoadCertificates(const char* certFile, const char* keyFile)
{
    //printf("Load certifcates. cert: %s / key: %s\n", certFile, keyFile);
    /* set the local certificate from CertFile */
    if (SSL_CTX_use_certificate_file(m_ctx, certFile, SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* set the private key from KeyFile (may be the same as CertFile) */
    if (SSL_CTX_use_PrivateKey_file(m_ctx, keyFile, SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* verify private key */
    if (!SSL_CTX_check_private_key(m_ctx))
    {
        fprintf(stderr, "Private key does not match the public certificate\n");
        abort();
    }
}

bool SslConnect::VerifyCertificate() {
    X509_STORE* store;
    X509* server_cert = SSL_get_peer_certificate(m_ssl);
    if (server_cert == NULL) {
        printf("Server does not have certificate.\n");
        return false;
    }

    //  Show server certificate info
    printf("Server certificate:\n");
    char* str = X509_NAME_oneline(X509_get_subject_name(server_cert), 0, 0);
    CHK_NULL(str);
    printf("\t subject: %s\n", str);
    OPENSSL_free(str);

    str = X509_NAME_oneline(X509_get_issuer_name(server_cert), 0, 0);
    CHK_NULL(str);
    printf("\t issuer: %s\n", str);
    OPENSSL_free(str);

    //  Verify server certificate
    if (!(store = X509_STORE_new()))
        printf("error creating store...\n");

    X509_STORE_CTX* vrfy_ctx = X509_STORE_CTX_new();
    int ret = X509_STORE_load_locations(store, PATH_ROOTCA_FILE, NULL);
    if (ret != 1) {
        printf("Error loading CA\n");
        return false;
    }

    X509_STORE_CTX_init(vrfy_ctx, store, server_cert, NULL);

    bool verified = (X509_verify_cert(vrfy_ctx) > 0);
    X509_STORE_CTX_free(vrfy_ctx);
    X509_STORE_free(store);
    X509_free(server_cert);

    return verified;
}

SSL* SslConnect::GetSSL() {
    return m_ssl;
}

bool SslConnect::loadCertification()
{
    m_ctx = this->GetSslCtx();
    if (m_ctx == NULL) {
        return false;
    }
    if (!loadCertificatesFromWCS(m_ctx))
    {
        // Windows Certificate Store에 key가 없는 경우
        //std::cerr << "certification could not be found.\n";
        //return -1;
        // FIXME: 개발용으로 아래의 코드를 쓰지만, 테스트 버전에서는 삭제되어야 한다.
        printf("FIXME to use personal certificate!\n");
        this->LoadCertificates(PATH_CERT_FILE, PATH_PRIVATE_KEY_FILE);
    }

    if (!SSL_CTX_load_verify_locations(m_ctx, "../Certificates/rootca.crt", NULL) ||
        !SSL_CTX_set_default_verify_paths(m_ctx)) {
        fprintf(stderr, "Fail to load rootCa crt for verifying client.\n");
        return false;
    }

    SSL_CTX_set_verify(m_ctx, SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE, SslConnect::verifyCertification);
    SSL_CTX_set_verify_depth(m_ctx, 1);

    return true;
}

bool SslConnect::acceptConnection(int sd)
{
    X509* client_cert = NULL;

    m_ssl = SSL_new(m_ctx);
    if (!m_ssl) {
        fprintf(stderr, "Fail to create SSL_new.\n");
        return false;
    }

    if (!SSL_set_fd(m_ssl, sd)) {
        fprintf(stderr, "Fail to set fd for ssl.\n");
        return false;
    }
    fprintf(stdout, "Waiting for client connection.\n");
    if (SSL_accept(m_ssl) == -1)
        return false;

    
    client_cert = SSL_get_peer_certificate(m_ssl);

    if (client_cert == NULL) {
        fprintf(stderr, "Client down not send client's crt.\n");
        return false;
    }
    else {
        char* str = X509_NAME_oneline(X509_get_subject_name(client_cert), 0, 0);
        if (str)
            fprintf(stdout, "Client's crt subject : %s\n", str);
        str = X509_NAME_oneline(X509_get_issuer_name(client_cert), 0, 0);
        if (str)
            fprintf(stdout, "Client's crt issuer : %s\n", str);
        X509_free(client_cert);
    }

    if (SSL_get_verify_result(m_ssl) != X509_V_OK) {
        fprintf(stderr, "Verifying client crt is failed.\n");
        return false;
    }
    else {
        fprintf(stdout, "Verifying client crt is success.\n");
    }
    return true;
}

int SslConnect::sslWriteFromImageToJpeg(cv::Mat Image)
{
    int result = 0;
    unsigned int imagesize;
    cv::imencode(".jpg", Image, sendbuff, param);
    imagesize = htonl(sendbuff.size());
    result = SSL_write(m_ssl, (unsigned char*)&imagesize, sizeof(imagesize));
    if (result < 0) {
        int errorNum = SSL_get_error(m_ssl, result);
        if (errorNum == SSL_ERROR_WANT_WRITE ||
            errorNum == SSL_ERROR_WANT_READ) {
            fprintf(stderr, "send ssl data, buffer is blocking, errno: %d.\n", errorNum);
        }
        else {
            fprintf(stderr, "send ssl data error, errno: %d.\n", errorNum);
        }
        return -1;
    }
    else if (result == 0) {
        int errorNum = SSL_get_error(m_ssl, result);
        if (errorNum == SSL_ERROR_ZERO_RETURN) {
            fprintf(stderr, "send ssl data error, peer closed.\n");
        }
        else {
            fprintf(stderr, "send ssl data error, errno: %d. \n", errorNum);
        }
    }
    result = SSL_write(m_ssl, (unsigned char*)sendbuff.data(), sendbuff.size());
    if (result < 0) {
        int errorNum = SSL_get_error(m_ssl, result);
        if (errorNum == SSL_ERROR_WANT_WRITE ||
            errorNum == SSL_ERROR_WANT_READ) {
            fprintf(stderr, "send ssl data, buffer is blocking, errno: %d.\n", errorNum);
        }
        else {
            fprintf(stderr, "send ssl data error, errno: %d.\n", errorNum);
        }
        return -1;
    }
    else if (result == 0) {
        int errorNum = SSL_get_error(m_ssl, result);
        if (errorNum == SSL_ERROR_ZERO_RETURN) {
            fprintf(stderr, "send ssl data error, peer closed.\n");
        }
        else {
            fprintf(stderr, "send ssl data error, errno: %d. \n", errorNum);
        }
    }
    //printf("Send data(size:%lu) success \n", sendbuff.size());
    return result;
}

int SslConnect::verifyCertification(int preverify, X509_STORE_CTX* ctx)
{
    char    buf[256];
    X509* cert;
    SSL* ssl;
    int err, depth;

    cert = X509_STORE_CTX_get_current_cert(ctx);
    err = X509_STORE_CTX_get_error(ctx);
    depth = X509_STORE_CTX_get_error_depth(ctx);

    X509_NAME_oneline(X509_get_subject_name(cert), buf, 256);

    if (depth >= 2) {
        err = X509_V_ERR_CERT_CHAIN_TOO_LONG;
        X509_STORE_CTX_set_error(ctx, err);
    }

    if (!preverify) {
        fprintf(stderr, "\n verify error:%d:%s:depth:%d:%s \n", err, X509_verify_cert_error_string(err), depth, buf);
    }

    if (!preverify && (err == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT)) {
        X509_NAME_oneline(X509_get_issuer_name(cert), buf, 256);
        fprintf(stdout, "issuer= %s\n", buf);
    }

    return preverify;

}