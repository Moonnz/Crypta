#include <SFML/Network.hpp>
#include <string.h>
#include <iostream>

#include <rsa.h>
#include <osrng.h>
#include <integer.h>
#include <sha.h>
#include <hex.h>
#include <filters.h>

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
  string byteToString(byte ss);

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
  SecByteBlock *key;
  SecByteBlock *iv;


};
