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

void DecodePrivateKey(const string&, RSA::PrivateKey&);
void DecodePublicKey(const string&, RSA::PublicKey&);
void Decode(const string&, BufferedTransformation&);

int main()
{
  AutoSeededRandomPool rnd;

  try
  {
    RSA::PrivateKey k1;
    DecodePrivateKey("rsa-private.key", k1);

    RSA::PublicKey k2;
    DecodePublicKey("test.aze", k2);

    cout << "Successfully loaded RSA keys" << endl;
    ///////////////////////////////////////////////
    if(!k1.Validate(rnd, 3))
      cout << "RSA PrivateKey validation failed" << endl;
    if(!k2.Validate(rnd, 3))
      cout << "RSA PublicKey validation failed" << endl;

    cout << "Successfully Validated RSA keys" << endl;
    //////////////////////////////////////////////
    if(k1.GetModulus() != k2.GetModulus() || k1.GetPublicExponent() != k2.GetPublicExponent())
      cout << "Key data did not round trip" << endl;
    cout << "Successfully round-tripped RSA keys" << endl;
  }

  catch(CryptoPP::Exception& e)
  {
    cerr << e.what() << endl;
    return -1;
  }

  /*std::ifstream is ("rsa-public.key", std::ifstream::binary);
  is.seekg(0, is.end);
  int length = is.tellg();
  is.seekg(0, is.beg);

  char * buffer = new char [length];

  cout << "Reading " << length << " charaters... " << endl;
  is.read(buffer, length);
  if(is)
    cout << "Reads Successfully" << endl;
  else
    cout << "Error: only" << is.gcount() << " could be read" << endl;
  is.close();

  sf::Packet pack;
  pack << buffer;
  sf::TcpSocket sock;
  sock.connect("localhost", 51000);
  sock.send(buffer, 396);*/
  return 0;
}

void DecodePrivateKey(const string& filename, RSA::PrivateKey& key)
{
  ByteQueue queue;

  Decode(filename, queue);
  key.BERDecodePrivateKey(queue, false, queue.MaxRetrievable());
}

void DecodePublicKey(const string& filename, RSA::PublicKey& key)
{
  ByteQueue queue;

  Decode(filename, queue);
  key.BERDecodePublicKey(queue, false, queue.MaxRetrievable());
}

void Decode(const string& filename, BufferedTransformation& bt)
{
  FileSource file(filename.c_str(), true);

  file.TransferTo(bt);
  bt.MessageEnd();
}
