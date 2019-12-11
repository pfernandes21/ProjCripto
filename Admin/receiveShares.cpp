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

	char command[COMMANDLENGTH], shareName[100];
	int aux=0;
	// Create a text string, which is used to output the text file
	string myText;

	// Read from the text file
	ofstream allShares("shares.txt");
	ifstream trusteeShare;

	//opening each trustee document
	for(int i=0; i<NUMBERTRUSTEES; i++){
		sprintf(shareName,"trustee%i/share%i.txt", i,i);
		trusteeShare.open(shareName);
		getline (trusteeShare, myText);
		allShares << myText;
		allShares << endl;
		trusteeShare.close();

	}

	

	//for(int i=0; i<NUMBERTRUSTEES; i++){
	//	trusteeShare[i].close();
	//}

	// Close the file
	allShares.close();

    
	
	
	
}
