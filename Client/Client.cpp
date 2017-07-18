#include "Client.h"

using namespace std;
using namespace sf;
using namespace CryptoPP;

Client::Client(string ip, int port)
{
  socket = new TcpSocket;
  pack = new Packet;
  selector = new sf::SocketSelector;
  status = new Socket::Status;
  *status = socket->connect(ip, port);

  if(*status == Socket::Done){
    cout << "Client connected" << endl;
    cout << "launchCrypt" << endl;
    launchCrypt();
    string toSend;
    while(1){
      cout << "Entrez un message a envoyer : " << endl;
      cin >> toSend;
      string toSendS = chiffre(toSend);
      *pack.clear();
      *pack << toSendS;
      socket.send(*pack);
    }
  }
  else{
    cout << "Client connection fail" << endl;
  }
}

string Serv::chiffre(string a){
  char p[a.length()];
  strcpy(p, a.c_str());
  CFB_Mode<AES>::Encryption Enc(key, AES::MAX_KEYLENGTH, iv);
  Enc.ProcessData((byte*)p, (byte*)p, a.length());
  return string(p);
}

string Serv::dechiffre(string a){
  char p[a.length()];
  strcpy(p, a.c_str());
  CFB_Mode<AES>::Decryption Dec(key, AES::MAX_KEYLENGTH, iv);
  Dec.ProcessData((byte*)p, (byte*)p, a.length());
  return string(p);
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

  cipherTextSize = e.CiphertextLength( sizeof(iv) );
  assert(0 != cipherTextSize);
  byte ivS[cipherTextSize];

  e.Encrypt(rng, (byte*)key, AES::MAX_KEYLENGTH, (byte*)keyS);
  e.Encrypt(rng, (byte*)iv, AES::BLOCKSIZE, (byte*)ivS);

  *pack << (int)sizeof(keyS);
  *pack << (int)sizeof(ivS);

  socket->send(*pack);
  pack->clear();

  pack->append(keyS, sizeof(keyS));
  socket->send(*pack);
  pack->clear();
  pack->append(ivS, sizeof(ivS));
  socket->send(*pack);
  pack->clear();

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
