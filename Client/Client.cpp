#include "Client.h"

using namespace std;
using namespace sf;
using namespace CryptoPP;

Client::Client(string ip, int port)
{
  socket = new TcpSocket;
  pack = new Packet;
  status = new Socket::Status;
  *status = socket->connect(ip, port);

  if(*status == Socket::Done){
    cout << "Client connected" << endl;
    cout << "launchCrypt" << endl;
    launchCrypt();
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

Client::~Client(){
  if(exist("kk.key"))
    std::remove("kk.key");
}

bool Client::exist(const string &file){
  ifstream f(file.c_str());
  return !f.fail();
}

void Client::launchCrypt()
{
  //Creation des variable de base pour le cryptage
  string Public, Val, hash;
  AutoSeededRandomPool rng;
  publicKey = new RSA::PublicKey;

  receiveKey();
  pr("Apparemment pas d'erreur \n Sa reste a voir.");
  RSAES_OAEP_SHA_Encryptor e(*publicKey);
  //Generation de la cles AES
  key = new byte[AES::MAX_KEYLENGTH];
  rng.GenerateBlock( key, AES::MAX_KEYLENGTH );
  //Generation d'un vecteur d'initialisation
  iv = new byte[AES::BLOCKSIZE];
  rng.GenerateBlock( iv, AES::BLOCKSIZE );

  pr("Test Cryptage clé");
  size_t cipherTextSize = e.CiphertextLength( sizeof(key) );
  assert(0 != cipherTextSize);
  byte keyS[cipherTextSize];

  e.Encrypt(rng, (byte*)key, AES::MAX_KEYLENGTH, (byte*)keyS);
  cout << sizeof(keyS) << endl << sizeof(key) << endl;
  *pack << sizeof(keyS);
  socket->send(*pack);
  *pack->clear();
  *pack->append(*keyS, sizeof(keyS));
  socket->send(*pack);
  *pack->clear();

  /*
  //Creation des variables pour la cles sous forme de string
  string keyS, ivS;
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

  cout << key << endl;
  cout << iv << endl;
  */

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

void Client::pr(string ss){
  cout << ss << endl;
}

void Client::DecodePublicKey(const string& filename, RSA::PublicKey& key)
{
  ByteQueue queue;

  Decode(filename, queue);
  key.BERDecodePublicKey(queue, false, queue.MaxRetrievable());
}

void Client::Decode(const string& filename, BufferedTransformation& bt)
{
  FileSource file(filename.c_str(), true);

  file.TransferTo(bt);
  bt.MessageEnd();
}

void Client::receiveKey(){
  int size;
  size_t a, b;
  sf::Packet *aa = new sf::Packet;
  socket->receive(*aa);
  *aa >> size;
  delete aa;
  char* buffer = new char[size];
  socket->receive(buffer, size, b);
  pr("La pas d'erreur");
  std::ofstream out("kk.key", std::ifstream::binary);
  out.write(buffer, size);
  out.close();
  DecodePublicKey("kk.key", *publicKey);
  std::remove("kk.key");
}

int main(){
  int a;
  cout << "Indiquer un port : " << endl;
  cin >> a;
  Client aa("localhost", a);
  return 0;
}
