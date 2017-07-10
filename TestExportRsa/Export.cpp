#include <SFML/Network.hpp>
#include <string.h>
#include <iostream>

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


void EncodePublicKey(const string&, const RSA::PublicKey&);
void EncodePrivateKey(const string&, const RSA::PrivateKey&);
void Encode(const string&, const BufferedTransformation&);
int main()
{
  AutoSeededRandomPool rnd;

  try
  {
    RSA::PrivateKey rsa3;
    RSA::PrivateKey rsa4;
    RSA::PrivateKey rsa8;

    cout << "Generation de la cles de 3072 bits ...";
    rsa3.GenerateRandomWithKeySize(rnd, 3072);
    cout << "Finis" << endl << "Generation de la cles de 4096 bits ...";
    rsa4.GenerateRandomWithKeySize(rnd, 4096);
    cout << "Finis" << endl << "Generation de la cles de 8192 bits ...";
    rsa8.GenerateRandomWithKeySize(rnd, 8192);
    cout <<"Finis" << endl;

    RSA::PublicKey rsa33(rsa3);
    RSA::PublicKey rsa44(rsa4);
    RSA::PublicKey rsa88(rsa8);

    EncodePublicKey("rsa-public-3072.key", rsa33);
    EncodePublicKey("rsa-public-4096.key", rsa44);
    EncodePublicKey("rsa-public-8192.key", rsa88);

    std::ifstream is3 ("rsa-public-3072.key", std::ifstream::binary);
    std::ifstream is4 ("rsa-public-4096.key", std::ifstream::binary);
    std::ifstream is8 ("rsa-public-8192.key", std::ifstream::binary);

    is3.seekg(0, is3.end);
    is4.seekg(0, is4.end);
    is8.seekg(0, is8.end);

    int l3 = is3.tellg();
    int l4 = is4.tellg();
    int l8 = is8.tellg();

    is3.close();
    is4.close();
    is8.close();

    cout << "Cles public de 3072bits : " << l3 << " chars" << endl;
    cout << "Cles public de 4096bits : " << l4 << " chars" << endl;
    cout << "Cles public de 8192bits : " << l8 << " chars" << endl;
  }

  catch(CryptoPP::Exception& e)
  {
    cerr << e.what() << endl;
    return -1;
  }

  /*sf::Packet pack;
  sf::TcpListener lis;
  if(lis.listen(51000) != sf::Socket::Done)
    cout << "error" << endl;
  sf::TcpSocket client;
  if(lis.accept(client) != sf::Socket::Done)
    cout << "errorr" << endl;
  char * buffer = new char[396];
  std::size_t a;
  client.receive(buffer, 396, a);
  std::ofstream out("test.aze", std::ofstream::binary);
  out.write(buffer, 396);
  out.close();
  lis.close();
  */
  return 0;
}

void EncodePrivateKey(const string& filename, const RSA::PrivateKey& key)
{
  ByteQueue queue;
  key.DEREncodePrivateKey(queue);

  Encode(filename, queue);
}

void EncodePublicKey(const string& filename, const RSA::PublicKey& key)
{
  ByteQueue queue;
  key.DEREncodePublicKey(queue);

  Encode(filename, queue);
}

void Encode(const string& filename, const BufferedTransformation& bt)
{
  FileSink file(filename.c_str());

  bt.CopyTo(file);
  file.MessageEnd();
}
