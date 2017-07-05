#include <SFML/Network.hpp>
#include <string.h>
#include <iostream>

#include <rsa.h>
#include <osrng.h>
#include <integer.h>
#include <sha.h>
#include <hex.h>

using namespace std;
using namespace sf;
using namespace CryptoPP;

class Serv{
public:
  Serv(int port);
  Serv();
  ~Serv(){};
  void setPort(int port);
  void launchCrypt();
  string hache(string ss);
  byte stringToByte(string ss);
  string byteToString(byte ss, int size);
  //int receive();
  //int send();

private:
  //Partie serveur;
  sf::TcpSocket *socket;
  sf::TcpListener *listener;
  string message;
  int portU;
  sf::Packet *pack;

  //Partie cryptage
  RSA::PrivateKey *privateKey;
  RSA::PublicKey *publicKey;

  string *pKey;
  byte *key;
  byte *iv;
};
