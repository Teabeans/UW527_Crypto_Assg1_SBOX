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

// initial S-Box values
unsigned char s1[ 16 ] = { 15, 8, 1, 9, 10, 4, 0, 3, 2, 11, 14, 12, 5, 6, 7, 13 };
unsigned char s2[ 16 ] = { 4, 8, 5, 2, 0, 9, 1, 3, 15, 7, 6, 14, 10, 13, 11, 12 };

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

	unsigned char val = a;
	val ^= 1UL << n;

	return val;

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

	// cipher
	sbox2 theBox;

	// load source into plaintext array
	loadPlaintext( "plaintext.txt" );

	// test Sbox load
	theBox.setSBox1( s1 );
	theBox.setSBox2( s2 );

	//std::cerr << "Twiddled: " << (unsigned int)twiddleBit( 0, 2 ) << std::endl;




	std::cerr << "Avalanche: " << calculateAvalanche( &theBox ) << std::endl;






//  theBox.renderPlaintext( 44 );

  // Test S-box encryption using K1 (rather than K2)
  // Key 1, Row 0
	unsigned char plaintext[ 4 ] = { 9, 4, 6, 6 };
    unsigned char ciphertext[ 4 ];
    theBox.encrypt( keys[ 0 ], plaintext, ciphertext );

	std::cerr << "Cipher text:" << std::endl;
	for( int i = 0 ; i < 4 ; i++ ) {
		std::cerr << std::setw(3) << (unsigned int)ciphertext[i] << " ";
		if( i == 3 ) {
			std::cerr << std::endl;
		}
	}


//  theBox.renderCiphertext( 44 );

//  sbox2 compareBox;
//  compareBox.loadSbox( "S1.txt", "S2.txt" );
//  compareBox.loadKeys( "keys.txt" );
//  compareBox.loadPlaintext( "plaintext_1bit.txt" );
//  for( int i = 0 ; i < 11 ; i++ ) {
//    compareBox.encrypt( "K1", i );
//  }
//  compareBox.renderCiphertext( 44 );
//
//  std::cerr << compareBox.cipherToString( 1, 10) << std::endl;
//  compareBox.renderBinaryString( compareBox.cipherToString(1, 10) );
//
//  std::cerr << theBox.avalancheCompare( "abcdeg", "abceeg" ) << std::endl << std::endl;
//
//  std::cerr << theBox.avalancheCompare( theBox.cipherToString( 1, 10), compareBox.cipherToString( 1, 10) ) << std::endl;

  return 1;
} // Closing main()





// End of file main.cpp
