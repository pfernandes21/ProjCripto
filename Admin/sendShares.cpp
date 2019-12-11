#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <string>
#include <iostream>
#include <fstream>
#include "defines.h"



using namespace std;

int main(int argc, char *argv[])
{

	char command[COMMANDLENGTH], shareName[22];
	int aux=0;
	// Create a text string, which is used to output the text file
	string myText;

	// Read from the text file
	ifstream shares("shares.txt");
	cout << "teste 1 \n";
	ofstream trusteeShare[NUMBERTRUSTEES];

	//opening each trustee document
	for(int i=0; i<NUMBERTRUSTEES; i++){
		sprintf(shareName,"share%i.txt", i);
		trusteeShare[i].open(shareName);

	}

	// Use a while loop together with the getline() function to read the file line by line
	while (getline (shares, myText)) {
  	// Output the text from the file
 		trusteeShare[aux]  << myText;
		aux++;
	}

	for(int i=0; i<NUMBERTRUSTEES; i++){
		trusteeShare[i].close();
		sprintf(command,"mv %s/share%i.txt %s/trustee%i/", sourcePath, i, sourcePath, i);
		system(command);
	}

	// Close the file
	shares.close();

	sprintf(command,"rm %s/shares.txt", sourcePath);
	system(command);

    
	
	
	
}
