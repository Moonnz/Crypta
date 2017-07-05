clear
echo "Compilation du client ..."
g++ Client/Client.cpp -o ClientC -I/usr/include/SFML -I/usr/include/cryptopp -lsfml-network -lsfml-system -lcryptopp -Wfatal-errors
echo "Compilation terminer"
echo "Compilation du serveur ..."
g++ Serv/Serv.cpp -o ServV -I/usr/include/SFML -I/usr/include/cryptopp -lsfml-network -lsfml-system -lcryptopp -Wfatal-errors
echo "Compilation terminer"
