#include <iostream>
#include <SFML/Network.hpp>

#include <rsa.h>
#include <osrng.h>
#include <integer.h>
#include <sha.h>
#include <hex.h>

using namespace std;
using namespace sf;
using namespace CryptoPP;

string phrase, port;
bool conn;
int sent(sf::TcpSocket& socket, string ss);
string hache(string ss);

int main()
{
  AutoSeededRandomPool rng;
  sf::TcpSocket socket;
  sf::Packet pack;

  InvertibleRSAFunction params;
  params.GenerateRandomWithKeySize(rng, 3072);
  RSA::PrivateKey privateKey(params);
  RSA::PublicKey publicKey(params);

  string Public, a;
  StringSink stringSink(Public);
  publicKey.DEREncode(stringSink);
  cout << "Entrée le port a utiliser : " << endl;
  cin >> a;
  Socket::Status status = socket.connect("localhost", stoi(a));
  if(status == Socket::Done){
    conn = true;
    cout << "Connected" << endl;
  }
  else{
    conn = false;
    cout << "Not Connected" << endl;
  }
  sent(socket, Public);
  return 0;
}

int sent(sf::TcpSocket& socket, string ss)
{
  string hash = hache(ss);
  if(conn == true)
  {
  sf::Packet pack;
  pack << ss;
  socket.send(pack);
  socket.receive(pack);
  string a;
  pack >> a;
  if(a == hash)
  {
    cout << "Packet receive good" << endl;
    return 0;
  }
  else
    cout << "Packet not receive good" << endl;
    return -1;
  }
  else
  {
    return -2;
  }
}

string hache(string ss)
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
