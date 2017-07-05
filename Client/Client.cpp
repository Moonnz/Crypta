#include "Client.h"

using namespace std;
using namespace sf;
using namespace CryptoPP;

Client::Client(string ip, int port)
{
  socket = new TcpSocket;
  pack = new Packet;
  Socket::Status status = socket->connect(ip, port);

  if(status == Socket::Done){
    cout << "Client connected" << endl;
  }
  else{
    cout << "Client connection fail" << endl;
  }

}


Client::Client()
{
  socket = new TcpSocket;
  pack = new Packet;
}

void Client::launchCrypt()
{
  //Creation des variable de base pour le cryptage
  string Public, Val, hash;
  AutoSeededRandomPool rng;
  publicKey = new RSA::PublicKey;

  //Reception de la cles public RSA
  socket->receive(pack);
  //Je place la cles recu dans un string
  *pack >> Val;
  //Je nettoye le sf::packet
  pack.clear();
  //Creation d'un filtre pour la cle
  StringSink publicSink(Val);
  //Decodage de la cles
  publicKey->DerDecode(publicSink);
  //Je calcul et hash la cles recu dans une variable
  hash = hache(Val);
  //Je place le hash dans un sf::packet
  *pack << hash;
  //J'envoyer ce packet
  socket->send(pack);
  //Je nettoye la variable et le packet
  Val.clear();
  pack->clear();
  //Generation de la cles AES
  key = new byte[AES::MAX_KEYLENGTH];
  rnd.GenerateBlock( key, key.size() );
  //Generation d'un vecteur d'initialisation
  iv = new byte[AES::BLOCKSIZE];
  rnd.GenerateBlock( iv, AES::BLOCKSIZE );

  *pack << key << iv;

}
string Client::hache(string ss){
  byte digest[SHA::DIGESTSIZE];
  SHA hash;
  hash.CalculateDigest(digest, (const byte*)ss.c_str(), ss.length());
  HexEncoder encoder;
  string output;
  encoder.Attach(new StringSink( output ));
  encoder.Put( digest, sizeof(digest) );
  encoder.MessageEnd();

  return output;
}

byte Serv::stringToByte(string ss){
  byte a[ss.length()];
  for(int i = 0; i < ss.length(); i++)
    a[i] == ss[i];
  return a;
}

string Serv::byteToString(byte ss, int size){
  string a;
  a.resize(size)
  for(int i = 0; i < size; i++)
    a[i] == ss[i];
  return a;
}

int main(){
  Client a("localhost", 50000);
  return 0;
}
