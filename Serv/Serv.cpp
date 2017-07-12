#include "Serv.h"

using namespace std;
using namespace sf;
using namespace CryptoPP;

Serv::Serv(int port)
{
  listener = new sf::TcpListener;
  socket = new sf::TcpSocket;
  pack = new Packet;
  if(listener->listen(port) != sf::Socket::Done)
    std::cout << "Error listen fail" << std::endl;
  else
  {
    std::cout << "Serveur lancer sur le port :" << listener->getLocalPort() << std::endl;
    portU = port;
    std::cout << "En attente de connexion..." << std::endl;
    listener->accept(*socket);
    std::cout << "Une connexion rentrante : " << socket->getRemoteAddress() << std::endl;
    launchCrypt();
  }
}

Serv::Serv()
{
  listener = new sf::TcpListener;
  socket = new sf::TcpSocket;
}

void Serv::setPort(int port)
{
  if(listener->listen(port) != sf::Socket::Done)
    std::cout << "Error listen fail" << std::endl;
  else{
      std::cout << "Serveur lancer sur le port :" << listener->getLocalPort() << std::endl;
      portU = port;
      std::cout << "En attente de connexion..." << std::endl;
      listener->accept(*socket);
      std::cout << "Une connexion rentrante : " << socket->getRemoteAddress() << std::endl;
  }
}

void Serv::launchCrypt()
{
  //Creation des variable de base pour le cryptage
  AutoSeededRandomPool rng;
  InvertibleRSAFunction params;
  string Public, Val;
  pKey = new string();
  params.GenerateRandomWithKeySize(rng, 2048);
  //Generation des cles RSA
  privateKey = new RSA::PrivateKey(params);
  publicKey = new RSA::PublicKey(params);

  //Encodage de la cles public dans une string en passant par un filtre
  sendKey();
  //Reception du packet dans la variable sf::packet "pack"
  socket->receive(*pack);
  //Je retire le string recu pour le mettre dans la variable Val et je vide le packet
  *pack >> Val;
  pack->clear();
  //Verification que la cles a était correctement recu
  if(Val == hache(Public)){
    cout << "Clé correctement echanger" << endl;
  }
  //Je nettoye la string Val
  Val.clear();

  /*
  //Creation des varaibles qui recevront la cles AES et l'IV
  key = new byte[AES::MAX_KEYLENGTH];
  iv = new byte[AES::BLOCKSIZE];
  //Je recois la cles AES crypter en RSA generer par le Client
  socket->receive(*pack);
  string keyS, ivS;
  //Je met la cles AES crypter dans la variable Val
  *pack >> keyS >> ivS;

  //Initialisation d'un decryptor RSAA pour recuperer la cles AES
  RSAES_OAEP_SHA_Decryptor d(*privateKey);
  //Decryptage de la cles
  StringSource s( keyS, true, new PK_DecryptorFilter( rng, d, new StringSink( keyS ) ) );
  StringSource ss( ivS, true, new PK_DecryptorFilter( rng, d ,new StringSink( ivS ) ) );

  pack->clear();

  *key = stringToByte(keyS);
  *iv = stringToByte(ivS);

  cout << key << endl;
  cout << iv << endl;
  */
}

string Serv::hache(string ss)
{
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
  byte* a = new byte[ss.length()];
  for(int i = 0; i < ss.length(); i++)
    a[i] == ss[i];
  return *a;
}

string Serv::byteToString(byte *ss, int size){
  string a;
  a.resize(size);
  for(int i = 0; i < size; i++)
    a[i] = ss[i];
  return a;
}

void Serv::pr(string ss){
  cout << ss << endl;
}

void Serv::sendKey(){
  EncodePublicKey("k.key", *publicKey)
  std::ifstream is("k.key", std::ifstream::binary);
  is.seekg(0, is.end);
  int size = is.tellg();
  char * buffer = new char[size];
  is.read(buffer, size);
  socket.send(size, sizeof(size));
  socket.send(buffer, size);
  is.close();
  std::remove("k.key");
  pack->clear();
}
void Serv::EncodePublicKey(const string& filename, const RSA::PublicKey& key)
{
  ByteQueue queue;
  key.DEREncodePublicKey(queue);

  Encode(filename, queue);
}

void Serv::Encode(const string& filename, const BufferedTransformation& bt)
{
  FileSink file(filename.c_str());

  bt.CopyTo(file);
  file.MessageEnd();
}

int main()
{
  Serv a(50000);
  return 0;
}
