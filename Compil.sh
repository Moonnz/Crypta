clear
echo "Compilation du client ..."
g++ Client/ClientCryptopp.cpp -o ClientCryptopp -I/usr/include/SFML -I/usr/include/cryptopp -lsfml-network -lsfml-system -lcryptopp -O6
echo "Compilation terminer"
echo "Compilation du serveur ..."
g++ Serv/ServeurCryptopp.cpp -o ServeurCryptopp -I/usr/include/SFML -I/usr/include/cryptopp -lsfml-network -lsfml-system -lcryptopp -O6
echo "Compilation terminer"
