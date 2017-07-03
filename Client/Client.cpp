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
  string Public, Val, hash;
  AutoSeededRandomPool rng;
  publicKey = new RSA::PublicKey;

  socket->receive(pack);
  *pack >> Val;
  pack.clear();
  StringSink publicSink(Val);
  publicKey->DerDecode(publicSink);
  hash = hache(Val);
  pack << hash;
  socket->send(pack);
  Val.clear();




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

int main(){
  Client a("localhost", 50000);
  return 0;
}
