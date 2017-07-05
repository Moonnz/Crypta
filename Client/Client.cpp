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
  socket->receive(*pack);
  //Je place la cles recu dans un string
  *pack >> Val;
  //Je nettoye le sf::packet
  pack->clear();
  //Creation d'un filtre pour la cle
  StringSink publicSink(Val);
  //Decodage de la cles
  publicKey->BERDecode(publicSink);
  //Je calcul et hash la cles recu dans une variable
  hash = hache(Val);
  //Je place le hash dans un sf::packet
  *pack << hash;
  //J'envoye ce packet
  socket->send(*pack);
  //Je nettoye la variable et le packet
  Val.clear();
  pack->clear();
  //Generation de la cles AES
  key = new byte[AES::MAX_KEYLENGTH];
  rng.GenerateBlock( key, AES::MAX_KEYLENGTH );
  //Generation d'un vecteur d'initialisation
  iv = new byte[AES::BLOCKSIZE];
  rng.GenerateBlock( iv, AES::BLOCKSIZE );

  //Creation des variables pour la cles sous forme de string
  string keyS, ivS;
  //Conversion des byte array en string
  keyS = byteToString(key, AES::MAX_KEYLENGTH);
  ivS = byteToString(iv, AES::BLOCKSIZE);
  //Cryptage de la cles et de l'iv
  RSAES_OAEP_SHA_Encryptor e(*publicKey);
  StringSource ss1( keyS, true, new PK_EncryptorFilter( rng, e, new StringSink( keyS ) ) );
  StringSource ss2( ivS, true, new PK_EncryptorFilter( rng, e, new StringSink( ivS ) ) );

  //DEBUG
  cout << keyS << endl << ivS << endl;
  //Je place les variables dans le packet
  *pack << keyS << ivS;
  //J'envois le paquet
  socket->send(*pack);


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

byte Client::stringToByte(string ss){
  byte* a = new byte[ss.length()];
  for(int i = 0; i < ss.length(); i++)
    a[i] == ss[i];
  return *a;
}

string Client::byteToString(byte *ss, int size){
  string a;
  a.resize(size);
  for(int i = 0; i < size; i++)
    a[i] = ss[i];
  return a;
}

int main(){
  Client a("localhost", 50000);
  return 0;
}
