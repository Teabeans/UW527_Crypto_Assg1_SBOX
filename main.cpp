//-------|---------|---------|---------|---------|---------|---------|---------|
//
// UW CSS 527 - Assg1 - Substitution Boxes
// main.cpp
//
//-------|---------|---------|---------|---------|---------|---------|---------|

//-----------------------------------------------------------------------------|
// Authorship
//-----------------------------------------------------------------------------|
//
// Tim Lum
// twhlum@gmail.com
//
// Matt Sell
//
// Created:  2020.01.15
// Modified: 2020.01.23 (TODO)
// For the University of Washington Bothell, CSS 527
// Winter 2020, Masters in Cybersecurity Engineering (MCSE)
//

//-----------------------------------------------------------------------------|
// File Description
//-----------------------------------------------------------------------------|
//
// Driver file for the sbox class

//-----------------------------------------------------------------------------|
// Package Files
//-----------------------------------------------------------------------------|
//
// See README.md

//-----------------------------------------------------------------------------|
// Useage
//-----------------------------------------------------------------------------|
//
// Compile with:
// $ ./compile.sh
//

//-------|---------|---------|---------|---------|---------|---------|---------|
//
//       DEFINES
//
//-------|---------|---------|---------|---------|---------|---------|---------|

#define DEBUG true

//-------|---------|---------|---------|---------|---------|---------|---------|
//
//       INCLUDES
//
//-------|---------|---------|---------|---------|---------|---------|---------|

#include "sbox2.h"

#include <iostream>
#include <string>
#include <sstream>
#include <fstream>
#include <stdio.h>
#include <iomanip>
#include <bitset>
#include <ctime>

// initial S-Box values
unsigned char s1[ 16 ] = { 15, 6, 14, 9, 1, 12, 0, 7, 5, 11, 3, 13, 2, 8, 4, 10 };
unsigned char s2[ 16 ] = { 10, 5, 15, 12, 13, 2, 8, 7, 1, 6, 4, 3, 14, 9, 11, 0 };

// keys
unsigned char keys[ 2 ][ 4 ] = {
		{ 10, 2, 3, 10 },
		{ 14, 15, 1, 8 }
};

// plaintext buffer
unsigned char plaintext[ 40 ];


//-------|---------|---------|---------|---------|---------|---------|---------|
//
//       PROGRAM DRIVER
//
//-------|---------|---------|---------|---------|---------|---------|---------|

int getNumBitsDifferent( unsigned char a, unsigned char b ) {

	// inspired by: https://www.geeksforgeeks.org/number-of-mismatching-bits-in-the-binary-representation-of-two-integers/

	int count = 0;

	for ( int i = 0; i < 3; i++ ) {

		// right shift both the numbers by 'i' and
		// check if the bit at the 0th position is different
		if ( ( ( a >> i ) & 1 ) != ( ( b >> i ) & 1 ) ) {
			count++;
		}

	}

	return count;

}

unsigned char twiddleBit( unsigned char a, int n ) {

	// inspired by: https://stackoverflow.com/questions/47981/how-do-you-set-clear-and-toggle-a-single-bit

	a ^= 1UL << n;

	return a;

}

void generateRandomArray( unsigned char array[ 16 ] ) {

	// inspired by: http://www.cplusplus.com/forum/beginner/95663/

	unsigned char newItem;

	// reset array values to something that will not be obtained
	for ( int i = 0; i < 16; i ++ ) {
		array[ i ] = 16;
	}

	for ( int i = 0; i < 16; i ++ ) {

		bool unique;

		do {

	    	unique = true;
	    	newItem = rand() % 16;

	    	for ( int j = 0;j < 16; j ++ ) {

	    		if( array[ j ] == newItem ) {
	    			unique = false;
	    			break;
	    		}

	    	}

	    } while ( unique == false );

	    array[ i ] = newItem;

	}

}

double calculateAvalanche( sbox2* cipher ) {

	double bitsChanged;

	// for each key...
	for ( int key = 0; key < 2; key ++ ) {

		// for each message
		for ( int msg = 0; msg < 10; msg ++ ) {

		    // make a copy of this plaintext message
		    unsigned char workingMessage[ 4 ];
		    workingMessage[ 0 ] = plaintext[ msg * 4 ];
		    workingMessage[ 1 ] = plaintext[ ( msg * 4 ) + 1 ];
		    workingMessage[ 2 ] = plaintext[ ( msg * 4 ) + 2 ];
		    workingMessage[ 3 ] = plaintext[ ( msg * 4 ) + 3 ];

			// get encrypted version of the message as a baseline
			unsigned char baselineEncrypted[ 4 ];
		    cipher->encrypt( keys[ key ], workingMessage, baselineEncrypted );

			// for each byte of the message
			for ( int msgByte = 0; msgByte < 4; msgByte ++ ) {

				// for each bit of the byte
				for ( int msgBit = 0; msgBit < 4; msgBit ++ ) {

					// "twiddle" the bit in the working message
					unsigned char wmb = workingMessage[ msgByte ];
					workingMessage[ msgByte ] = twiddleBit( wmb, msgBit );

					// get this new encrypted value
					unsigned char encryptedTwiddled[ 4 ];
					cipher->encrypt( keys[ key ], workingMessage, encryptedTwiddled );

					// count how many bits are different, for each byte
					for ( int diffByte = 0; diffByte < 4; diffByte ++ ) {
						bitsChanged += getNumBitsDifferent( baselineEncrypted[ diffByte ], encryptedTwiddled[ diffByte ] );
					}

					// return the working message back to what it was
					workingMessage[ msgByte ] = twiddleBit( workingMessage[ msgByte ], msgBit );

				}

			}

		}

		// avalanche is the number of bits changed divided by total possible
		return bitsChanged / ( 2.0 * 10.0 * 16.0 * 16.0 );

	}

}

void loadPlaintext( std::string filename ) {

	if( DEBUG ) {
		std::cerr << "Loading plaintext from '" << filename << "'... ";
	}

	// Load 'filename' to a filestream ('plaintextFile')
	std::ifstream plaintextFile;
	plaintextFile.open( filename );
	std::string nibble;
	int currPos = 0;

	// While there are characters in the filestream...
	while( !plaintextFile.eof() ) {

		// Snip off a token (4 bits or 1 nibble)
		plaintextFile >> nibble;

		// Save the nibble as an unsigned char to the plaintext buffer
		plaintext[ currPos ] = (unsigned char)std::stoi( nibble, nullptr, 2 );

		// Advance buffer write position by 1
		currPos++;

	}

	if( DEBUG ) {

		std::cerr << "Plaintext loaded! " << std::endl;
		std::cerr << "  As ints:";
		for( int i = 0 ; i < currPos-1 ; i++ ) {
			// Next set of 4
			if( i % 4 == 0 ) {
				std::cerr << std::endl << "    MSG" << std::setw(3) << (i / 4) << ": [";
			}
			std::cerr << std::setw(3) << (unsigned int)plaintext[ i ];
			if( i % 4 != 3 ) {
				std::cerr << ", ";
			}
			if( i % 4 == 3 ) {
				std::cerr << " ]";
			}
		}

		std::cerr << std::endl << std::endl;

	}

}

int main() {

	srand( time ( NULL ) );

	// cipher
	sbox2 theBox;

	// load source into plaintext array
	loadPlaintext( "plaintext.txt" );

	// test Sbox initial values load
	theBox.setSBox1( s1 );
	theBox.setSBox2( s2 );

	// get initial avalanche from provided S-Box initial values
	double maxAvalanche = 0.0;
	maxAvalanche = calculateAvalanche( &theBox );
	std::cerr << "Initial: " << maxAvalanche << std::endl;

	// repeat avalanche calculations looking for better S-Box values
	unsigned char newSBox1[ 16 ];
	unsigned char newSBox2[ 16 ];
	while ( true ) {

		// generate random S-Box values
		generateRandomArray( newSBox1 );
		generateRandomArray( newSBox2 );

		// set cipher to use the random boxes
		theBox.setSBox1( newSBox1 );
		theBox.setSBox2( newSBox2 );

		// calculate avalanche
		double avalanche = calculateAvalanche( &theBox );

		// better?
		if ( avalanche >  maxAvalanche ) {

			std::cerr << "Better: " << avalanche << std::endl;
			maxAvalanche = avalanche;

			// display better S-Box values
			std::cerr << "Better S1: ";
			for( int i = 0 ; i < 16 ; i++ ) {
				std::cerr << std::setw(3) << (unsigned int)newSBox1[i] << " ";
				if( i == 15 ) {
					std::cerr << std::endl;
				}
			}

			std::cerr << "Better S2: ";
			for( int i = 0 ; i < 16 ; i++ ) {
				std::cerr << std::setw(3) << (unsigned int)newSBox2[i] << " ";
				if( i == 15 ) {
					std::cerr << std::endl;
				}
			}

			std::cerr << std::endl << std::endl;

		}

	}

  return 1;

} // Closing main()





// End of file main.cpp
