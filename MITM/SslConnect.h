#ifndef SSL_CONNECT_H
#define SSL_CONNECT_H

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <opencv2/core/core.hpp>
#include <openssl/x509.h>

class SslConnect {
private:
	bool isServer = false;
	const SSL_METHOD* method;

	SSL* m_ssl;
	SSL_CTX* m_ctx;

	SSL_CTX* GetSslCtx(void);
	void LoadCertificates(const char* CertFile, const char* KeyFile);
	bool VerifyCertificate();

public:
	SslConnect(bool _isServer);
	~SslConnect();

	bool InitializeCtx();
	bool Connect(int fd);
	SSL* GetSSL();

	bool loadCertification();
	bool acceptConnection(int sd);
	int sslWriteFromImageToJpeg(cv::Mat Image);
	static int verifyCertification(int preverify, X509_STORE_CTX* ctx);

};

#endif // SSL_CONNECT_H