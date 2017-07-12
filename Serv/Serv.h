#include <SFML/Network.hpp>
#include <string.h>
#include <iostream>
#include <fstream>

#include <rsa.h>
#include <osrng.h>
#include <integer.h>
#include <sha.h>
#include <hex.h>
#include <queue.h>
#include <files.h>
#include <cryptlib.h>

using namespace std;
using namespace sf;
using namespace CryptoPP;

class Serv{
public:
  Serv(int port);
  Serv();
  ~Serv(){};
  void setPort(int);
  void launchCrypt();
  string hache(string);

  byte stringToByte(string);
  string byteToString(byte*, int);
  void pr(string ss);
  void EncodePrivateKey(const string&, const RSA::PublicKey&)
  void Encode(const string&, BufferedTransformation&);


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
