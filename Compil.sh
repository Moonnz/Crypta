clear
echo "Compilation du client ..."
g++ Client/Client.cpp -o build/ClientC -I/usr/include/SFML -I/usr/include/cryptopp -lsfml-network -lsfml-system -lcryptopp
echo "Compilation terminer"
echo "Compilation du serveur ..."
g++ Serv/Serv.cpp -o build/ServV -I/usr/include/SFML -I/usr/include/cryptopp -lsfml-network -lsfml-system -lcryptopp
echo "Compilation terminer"
