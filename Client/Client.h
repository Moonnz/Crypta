#include <SFML/Network.hpp>
#include <string.h>
#include <iostream>
#include <fstream>

#include <rsa.h>
#include <osrng.h>
#include <integer.h>
#include <sha.h>
#include <hex.h>
#include <filters.h>
#include <queue.h>
#include <files.h>
#include <cryptlib.h>

using namespace std;
using namespace sf;
using namespace CryptoPP;

class Client{
public:
  Client(string ip, int port);
  Client();
  ~Client(){};
  void setPort(int port);
  void launchCrypt();
  string hache(string ss);

  byte stringToByte(string ss);
  string byteToString(byte *ss, int size);
  void pr(string ss);
  void DecodePublicKey(const string&, RSA::PublicKey&);
  void Decode(const string&, BufferedTransformation&);
  void receiveKey();

  //int receive();
  //int send();

private:
  //Partie serveur;
  sf::TcpSocket *socket;
  string message;
  int portU;
  sf::Packet *pack;

  //Partie cryptage
  RSA::PublicKey *publicKey;

  string *pKey;
  byte *key;
  byte *iv;


};
