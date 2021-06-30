//------------------------------------------------------------------------------------------------
// File: RecvImageTCP.cpp
// Project: LG Exec Ed Program
// Versions:
// 1.0 April 2017 - initial version
// This program receives a jpeg image via a TCP Stream and displays it. 
//----------------------------------------------------------------------------------------------
#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <iostream>


#include <opencv2/core/core.hpp>
#include <opencv2/highgui/highgui.hpp>

#include <iostream>
#include "NetworkTCP.h"
#include "TcpSendRecvJpeg.h"
#include "SslConnect.h"

#define SECURE_MODE         (true)
#define MAX_CONNECT_TRIAL   (100)
#define PORT_NUMI            (5000)
#define PORT_NUMS            "5000"
enum { LISTEN_FAIL = -1, ACCEPT_FAIL = -2, VERIFY_FAIL = -3, SEND_FAIL = -4, CONNECT_FAIL = -5 };

using namespace cv;
using namespace std;
//----------------------------------------------------------------
// main - This is the main program for the RecvImageUDP demo 
// program  contains the control loop
//-----------------------------------------------------------------
DWORD WINAPI fake_client(LPVOID lpParam);

inline bool file_exists(const std::string& name) {
	if (FILE* file = fopen(name.c_str(), "r")) {
		fclose(file);
		return true;
	}
	else {
		return false;
	}
}

class MITM_Server
{
private:
	TTcpListenPort* TcpListenPort = NULL;
	TTcpConnectedPort* TcpConnectedPort = NULL;
	struct sockaddr_in cli_addr;
	socklen_t          clilen;
	SslConnect* connection = NULL;
	cv::VideoCapture* videoCapture = nullptr;
	std::string filename;

public:
	MITM_Server(std::string& videoFilename)
	{
		if (connection != NULL) return;
		connection = new SslConnect(true);
		if (connection == NULL) {
			fprintf(stderr, "Fail to start service [Internal Error : Fail to create SslConnect.]\n");
			return;
		}

		if (!connection->loadCertification()) {
			fprintf(stderr, "Fail to start service [Internal Error : Load server cert/key is failed.\n");
			delete connection;
			return;
		}
		else {
			fprintf(stderr, "Loading server certification and private key is success.\n");
		}

		filename = videoFilename;
		return;
	}
	~MITM_Server()
	{
		if (connection)
			delete connection;
		if (TcpListenPort) {
			CloseTcpListenPort(&TcpListenPort);
			TcpListenPort = NULL;
		}
	}
	int listen()
	{
		clilen = sizeof(cli_addr);
		fprintf(stdout, "Waiting for connection from client.\n");
		if ((TcpListenPort = OpenTcpListenPort(PORT_NUMI)) == NULL)
		{
			fprintf(stderr, "OpenTcpListenPortFailed.\n");
			return LISTEN_FAIL;
		}
		return 0;
	}
	int accept()
	{
		if ((TcpConnectedPort = AcceptTcpConnection(TcpListenPort, &cli_addr, &clilen)) == NULL)
		{
			printf("AcceptTcpConnection Failed\n");
			return ACCEPT_FAIL;
		}

		fprintf(stdout, "Monitoring system is connected\n");

		if (!connection->acceptConnection(TcpConnectedPort->ConnectedFd)) {
			fprintf(stderr, "Fail to verify client.\n");
			return VERIFY_FAIL;
		}
		else {
			fprintf(stdout, "client is connected and verified.\n");
		}

		if (filename == "")
		{
			videoCapture = new VideoCapture(0, 0);
		}
		else
		{
			videoCapture = new VideoCapture(filename, 0);
		}

		fprintf(stdout, "Now streaming is started.\n");
		return 0;
	}
	int sendImage()
	{
		cv::Mat frame;
		*videoCapture >> frame;
		if (frame.empty()) {
			std::cout << "Empty frame! Exiting...\n Try restarting nvargus-daemon by "
				"doing: sudo systemctl restart nvargus-daemon" << std::endl;
			exit(-1);
		}

		if (connection->sslWriteFromImageToJpeg(frame) <= 0)
			return SEND_FAIL;
		return 0;
	}
	int disconnect()
	{
		if (TcpConnectedPort) {
			CloseTcpConnectedPort(&TcpConnectedPort);
			TcpConnectedPort = NULL;
		}

		if (videoCapture != nullptr)
		{
			delete videoCapture;
			videoCapture = nullptr;
		}

		fprintf(stdout, "Connection is closed.\n");
		return 0;
	}
};

class MITM_Client
{
private:
	SslConnect* ssl = NULL;
	int connect_trial = 0;
	TTcpConnectedPort* TcpConnectedPort = NULL;
	const char* hostname = NULL;
	Mat Image;

	HANDLE hThread = 0;
	DWORD tid;

public:
	MITM_Client(const char* _hostname) : hostname(_hostname)
	{
	}
	int connect()
	{
		fprintf(stdout, "[Clinet] Connect to Server.\n");
		if (!hThread)
			hThread = CreateThread(NULL, 0, fake_client, (LPVOID)hostname, 0, &tid);

		return 0;

		ssl = new SslConnect(false);
		ssl->InitializeCtx();


		do {
			connect_trial++;
			printf("Tring to connect(%d)...\n", connect_trial);
			if ((TcpConnectedPort = OpenTcpConnection(hostname, PORT_NUMS)) == NULL)  // Open TCP Network port
			{
				printf("Error on OpenTcpConnection\n");
				//  Terminate if it met maximum trial
				if (connect_trial == MAX_CONNECT_TRIAL)
				{
					printf("Unable to connect. Terminate.\n");
					if (ssl != NULL) {
						delete ssl;
						ssl = NULL;
					}
					return CONNECT_FAIL;
				}
				Sleep(5000);
			}
		} while (TcpConnectedPort == NULL);
		connect_trial = 0;

		if (SECURE_MODE && ssl != NULL)
		{
			if (!ssl->Connect(TcpConnectedPort->ConnectedFd)) {
				printf("Failed to Connect on SSL\n");
				return CONNECT_FAIL;
			}
		}

		namedWindow("MServer", WINDOW_AUTOSIZE);// Create a window for display.

		return 0;
	}
	int recvImage()
	{
		return 0;

		bool retvalue = SslRecvImageAsJpeg(ssl->GetSSL(), &Image);
		if (retvalue) imshow("MServer", Image); // If a valid image is received then display it

		if (!retvalue)
		{
			printf("Invalid image\n");
			return -1;
		}

		return 0;
	}
	int disconnect()
	{
		if (hThread)
		{
			CloseHandle(hThread);
			hThread = 0;
		}

		if (TcpConnectedPort != NULL)
		{
			CloseTcpConnectedPort(&TcpConnectedPort); // Close network port;
			TcpConnectedPort = NULL;
		}
		if (ssl != NULL)
		{
			delete ssl;
			ssl = NULL;
		}
		return 0;
	}
};


int monitoringsystem_main(const char* hostname)
{
	TTcpConnectedPort* TcpConnectedPort = NULL;
	SslConnect* ssl = NULL;
	bool retvalue;
	bool do_exit = false;
	int connect_trial = 0;

#if (SECURE_MODE)
	ssl = new SslConnect(false);
	ssl->InitializeCtx();
#endif // (SECURE_MODE)

	do {
		//  Try until connection established
		do {
			connect_trial++;
			printf("Tring to connect(%d)...\n", connect_trial);
			if ((TcpConnectedPort = OpenTcpConnection(hostname, PORT_NUMS)) == NULL)  // Open TCP Network port
			{
				printf("Error on OpenTcpConnection\n");
				//  Terminate if it met maximum trial
				if (connect_trial == MAX_CONNECT_TRIAL)
				{
					printf("Unable to connect. Terminate.\n");
					if (ssl != NULL) {
						delete ssl;
						ssl = NULL;
					}
					return(-1);
				}
				Sleep(5000);
			}
		} while (TcpConnectedPort == NULL);
		connect_trial = 0;

		if (SECURE_MODE && ssl != NULL)
		{
			if (!ssl->Connect(TcpConnectedPort->ConnectedFd)) {
				printf("Failed to Connect on SSL\n");
				break;
			}
		}

		namedWindow("MServer", WINDOW_AUTOSIZE);// Create a window for display.

		Mat Image;
		do {
			if (ssl != NULL)
			{
				retvalue = SslRecvImageAsJpeg(ssl->GetSSL(), &Image);
			}
			else
			{
				retvalue = TcpRecvImageAsJpeg(TcpConnectedPort, &Image);
			}
			if (retvalue) imshow("MServer", Image); // If a valid image is received then display it
			else
			{
				printf("Invalid image\n");
				CloseTcpConnectedPort(&TcpConnectedPort); // Close network port;
				break;
			}
			do_exit = (waitKey(10) != 'q');
		} while (do_exit); // loop until user hits quit

		//  It server has been down, disconnect port
	} while (do_exit);

	printf(" Closing... \n");
	CloseTcpConnectedPort(&TcpConnectedPort); // Close network port;
	if (ssl != NULL)
	{
		delete ssl;
		ssl = NULL;
	}

	return 0;
}


DWORD WINAPI fake_client(LPVOID lpParam)
{
	return monitoringsystem_main((const char*)lpParam);
}

int main(int argc, char* argv[])
{
	if (argc < 2)
	{
		fprintf(stderr, "usage %s hostname video_filename\n", argv[0]);
		exit(0);
	}

	const char* hostname = argv[1];
	std::string videoFile = "";

	if (argc == 3)
	{
		videoFile = std::string(argv[2]);

		if (videoFile.empty() || file_exists(videoFile) == false) {
			fprintf(stderr, "File is not exist. Check file to play video file(%s) \n", argv[2]);
			exit(0);
		}
	}

	MITM_Server server(videoFile);
	MITM_Client client(hostname);

	int rv = server.listen();
	if (rv == LISTEN_FAIL) return -1;
	while (true)
	{
		rv = server.accept();
		if (rv == ACCEPT_FAIL) continue;
		if (rv == VERIFY_FAIL) continue;

		client.connect();
		int nbFrames = 0;

		while (true)
		{
			if (server.sendImage() == SEND_FAIL)
				break;
			client.recvImage();
		}
		client.disconnect();
		server.disconnect();
	}

	return 0;
}
//-----------------------------------------------------------------
// END main
//-----------------------------------------------------------------
//-----------------------------------------------------------------
// END of File
//-----------------------------------------------------------------
