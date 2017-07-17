#include "Serv.h"

using namespace std;
using namespace sf;
using namespace CryptoPP;

Serv::~Serv(){
  listener->close();
}

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
  pack = new Packet;
  if(listener->listen(0) != sf::Socket::Done)
    std::cout << "Error listen fail" << std::endl;
  else
  {
    std::cout << "Serveur lancer sur le port :" << listener->getLocalPort() << std::endl;
    portU = listener->getLocalPort();
    std::cout << "En attente de connexion..." << std::endl;
    listener->accept(*socket);
    std::cout << "Une connexion rentrante : " << socket->getRemoteAddress() << std::endl;
    launchCrypt();
  }
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
  params.GenerateRandomWithKeySize(rng, 4096);
  //Generation des cles RSA
  privateKey = new RSA::PrivateKey(params);
  publicKey = new RSA::PublicKey(params);

  //Encodage de la cles public dans une string en passant par un filtre
  sendKey();
  pr("Apparemment pas d'erreur non plus \n Sa reste a voir.");

  socket->receive(*pack);
  int ivSize, keySize;
  *pack >> ivSize;
  *pack >> keySize;

  pack->clear();

  //Creation des varaibles qui recevront la cles AES et l'IV
  byte keyS[keySize];
  byte ivS[ivSize];

  pr("Reception clés...");
  socket->receive(*pack);
  memcpy(keyS, pack->getData(), pack->getDataSize());
  pack->clear();

  pr("Reception iv...");
  socket->receive(*pack);
  memcpy(ivS, pack->getData(), pack->getDataSize());
  pack->clear();

  //Initialisation d'un decryptor RSAA pour recuperer la cles AES
  RSAES_OAEP_SHA_Decryptor d(*privateKey);
  //Decryptage de la cles
  size_t sizeR = d.MaxPlaintextLength( sizeof(keyS) );
  key = new byte[sizeR];
  pr("Decryptage clé...");
  d.Decrypt( rng, (byte*)keyS, sizeof(keyS), (byte*)key );
  sizeR = d.MaxPlaintextLength( sizeof(ivS) );
  iv = new byte[sizeR];
  pr("Decryptage iv...");
  d.Decrypt( rng, (byte*)ivS, sizeof(ivS), (byte*)iv );

  string ssa = "Hello world!";
  char plainText[ssa.length()];
  strcpy(plainText, ssa.c_str());
  cout << plainText << endl;
  CFB_Mode<AES>::Encryption Enc(key, AES::MAX_KEYLENGTH, iv);
  Enc.ProcessData((byte*)plainText, (byte*)plainText, ssa.length());
  cout << ssa << endl;
  cout << plainText << endl;
  CFB_Mode<AES>::Decryption Dec(key, AES::MAX_KEYLENGTH, iv);

  listener->close();
}

string Serv::chiffre(string a){
  char p[a.length()];
  strcpy(p, a.c_str());
  CFB_Mode<AES>::Encryption Enc(key, AES::MAX_KEYLENGTH, iv);
  Enc.ProcessData((byte*)p, (byte*)p, a.length());
  return string(p);
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
  EncodePublicKey("k.key", *publicKey);
  std::ifstream is("k.key", std::ifstream::binary);
  is.seekg(0, is.end);
  int size = is.tellg();
  is.seekg(0, is.beg);
  char * buffer = new char[size];
  is.read(buffer, size);
  sf::Packet *aa = new sf::Packet;
  *aa << size;
  socket->send(*aa);
  delete aa;
  is.close();
  std::remove("k.key");
  socket->send(buffer, size);
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
  Serv a(0);
  return 0;
}
