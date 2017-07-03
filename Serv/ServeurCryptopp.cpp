#include <iostream>
#include <SFML/Network.hpp>
#include <string>

#include <rsa.h>
#include <osrng.h>
#include <integer.h>
#include <sha.h>
#include <hex.h>

using namespace std;
using namespace sf;
using namespace CryptoPP;

string phrase;
string hache(string ss);
int main()
{
    TcpListener serveur;
    TcpSocket client;
    sf::Packet pack;
    if(serveur.listen(Socket::AnyPort) != sf::Socket::Done)
        cout << "Error" << endl;
    else
    {
    cout << "Le port utiliser est le : " << serveur.getLocalPort() << endl;
    cout << "En attente de connexion..." << endl;
    serveur.accept(client);
    cout<<"Une connexion entrante : "<<client.getRemoteAddress()<<endl;
    client.receive(pack);
    pack >> phrase;
    pack.clear();
    string x = hache(phrase);
    pack << x;
    client.send(pack);
    cout << "OK" << endl;
    }

    return 0;
}

int receive(sf::TcpSocket& socket, string ss)
{
  string hash;
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
