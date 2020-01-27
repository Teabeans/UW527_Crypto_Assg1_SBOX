//-------|---------|---------|---------|---------|---------|---------|---------|
//
// UW CSS 527 - Assg1 - Substitution Boxes
// sbox.cpp
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
// Implementation file for the sbox class

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

#define DEBUG false
#define MAX_MSG_LENGTH 1024

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

//-------|---------|---------|---------|---------|---------|---------|---------|
//
//       PUBLIC FIELDS
//
//-------|---------|---------|---------|---------|---------|---------|---------|

//-------|---------|---------|---------|---------|---------|---------|---------|
//
//       CONSTRUCTOR / DESTRUCTOR
//
//-------|---------|---------|---------|---------|---------|---------|---------|

// (+) --------------------------------|
// #sbox( )
// ------------------------------------|
// Desc:    Default constructor for an sbox object
// Params:  None
// PreCons: None
// PosCons: An sbox object has been constructed and zeroed
// RetVal:  None
sbox2::sbox2( ) {
} // Closing sbox()

// (+) --------------------------------|
// #~sbox( )
// ------------------------------------|
// Desc:    Destructor for an sbox object
// Params:  None
// PreCons: None
// PosCons: None
// RetVal:  None
sbox2::~sbox2( ) {
} // Closing ~sbox()

//-------|---------|---------|---------|---------|---------|---------|---------|
//
//       PUBLIC METHOD IMPLEMENTATIONS
//
//-------|---------|---------|---------|---------|---------|---------|---------|

//-------|---------|---------|---------|---------|---------|
//       WORKERS
//-------|---------|---------|---------|---------|---------|

// (+) --------------------------------|
// #encrypt( )
// ------------------------------------|
// Desc:    Encrypts the plaintext buffer into the ciphertext buffer
// Params:  std::string arg1 - The key to use (K1 or K2)
//          int arg2         - The plaintext row to encrypt
// PreCons: None
// PosCons: To perform correctly, the sbox object should be initialized properly
// RetVal:  None
void sbox2::encrypt( unsigned char key[ 4 ], unsigned char plaintext[ 4 ], unsigned char ciphertext[ 4 ] ) {

	if( DEBUG ) {
		std::cerr << "Key:" << std::endl;
		for( int i = 0 ; i < 4 ; i++ ) {
			std::cerr << std::setw(3) << (unsigned int)key[i] << " ";
			if( i == 3 ) {
				std::cerr << std::endl;
			}
		}
	}

	// Implement the cipher to find the appropriate indices
	unsigned char cipherIndex[4];
	cipherIndex[0] = plaintext[1] ^ key[0];
	cipherIndex[1] = plaintext[3] ^ key[2];
	cipherIndex[2] = plaintext[0] ^ key[1];
	cipherIndex[3] = plaintext[2] ^ key[3];

	// Read out from S1 and S2 at the appropriate locations to find the cipher character
	ciphertext[0] = S1Linear[cipherIndex[0]];
	ciphertext[1] = S2Linear[cipherIndex[1]];
	ciphertext[2] = S1Linear[cipherIndex[2]];
	ciphertext[3] = S2Linear[cipherIndex[3]];

	// Report results
	if( DEBUG ) {
		std::cerr << "----- ENCRYPTION COMPLETE -----" << std::endl;
		std::cerr << "  [";
		for( int i = 0 ; i < 4 ; i++ ){
			std::cerr << std::setw(3) << (unsigned int)ciphertext[i];
			if( i % 4 != 3 ) {
				std::cerr << ",";
			}
		}
		std::cerr << " ]" << std::endl << std::endl;
	}

} // Closing encrypt()

//-------|---------|---------|---------|---------|---------|
//       CONVERTERS
//-------|---------|---------|---------|---------|---------|

// (+) --------------------------------|
// #convertBinaryToInt( )
// ------------------------------------|
// Desc:    Converts a binary string to its integer equivalent
// Params:  std::string arg1 - The binary string to convert
// PreCons: Arg1 must be a valid binary string
// PosCons: None
// RetVal:  int - The integer equivalent of arg1
int sbox2::convertBinaryToInt( std::string binaryString ) {
  unsigned int retval = std::stoi( binaryString, nullptr, 2);
  return retval;
} // Closing convertBinaryToInt()

// (+) --------------------------------|
// #convertIntToChar( )
// ------------------------------------|
// Desc:    Convert an integer to its char equivalent
// Params:  int arg1 - The integer to convert to ASCII char
// PreCons: Arg1 must be within range 0 to 255 (inclusive)
// PosCons: None
// RetVal:  char - The ASCII char equivalent
char sbox2::convertIntToChar( int input ) {
  char retchar = (char)input;
  return retchar;
} // Closing convertIntToChar()

//-------|---------|---------|---------|---------|---------|
//       RENDERERS
//-------|---------|---------|---------|---------|---------|

// (+) --------------------------------|
// #cipherToString( int, int )
// ------------------------------------|
// Desc:    Convert a selection of rows to their binary string equivalent
// Params:  int arg1 - The first row to convert (inclusive)
//          int arg2 - The final row to convert (inclusive)
// PreCons: None
// PosCons: No whitespaces are included; each char is 4 bits
// RetVal:  std::string - The binary string representation of the ciphertext
std::string sbox2::cipherToString( int minRow, int maxRow ) {
  std::stringstream ss;
  for( int currRow = minRow ; currRow <= maxRow ; currRow++ ) {
    for( int col = 0 ; col < 4 ; col++ ) {
      int currChar = (unsigned int)this->ciphertext[ ((currRow*4) + col) ];
      ss << std::bitset<4>(currChar).to_string();
    }
  }
  return ss.str();
} // closing cipherToString()

void sbox2::renderBinaryString( std::string bitSequence ) {
  for( int i = 0 ; i < bitSequence.length() ; i++ ) {
    std::cerr << bitSequence.at(i);
    if( i % 4 == 3 ) {
      std::cerr << " ";
    }
    if( i % 16 == 15 ) {
      std::cerr << std::endl;
    }
  }
} // Closing cipherToString()

// (+) --------------------------------|
// #renderPlaintext( )
// ------------------------------------|
// Desc:    Renders the Sbox's plaintext buffer
// Params:  int arg1 - The number of characters of the plaintext to render
// PreCons: None
// PosCons: None
// RetVal:  None
void sbox2::renderPlaintext( int length) {
  if( DEBUG ) {
    std::cerr << "Rendering plaintext..." << std::endl;
    std::cerr << "--------|--------|-------- PLAINTEXT --------|--------|--------" << std::endl;
  }
  for( int i = 0 ; i < length ; i++ ) {
    std::cerr << std::setw(3) << (unsigned int)this->plaintext[i];
    if( i % 4 == 3 ) {
      std::cerr << std::endl;
    }
  }
  if( DEBUG ) {
    std::cerr << "--------|--------|-------- PLAINTEXT --------|--------|--------" << std::endl;
  }
  std::cerr << std::endl;
} // Closing renderPlaintext()

// (+) --------------------------------|
// #renderCiphertext( )
// ------------------------------------|
// Desc:    Renders the Sbox's ciphertext buffer
// Params:  int arg1 - The number of characters of the ciphertext to render
// PreCons: None
// PosCons: None
// RetVal:  None
void sbox2::renderCiphertext( int length ) {
  if( DEBUG ) {
    std::cerr << "Rendering ciphertext..." << std::endl;
    std::cerr << "--------|--------|-------- CIPHERTEXT --------|--------|--------" << std::endl;
  }
  for( int i = 0 ; i < length ; i++ ) {
    std::cerr << std::setw(3) << (unsigned int)this->ciphertext[i];
    if( i % 4 == 3 ) {
      std::cerr << std::endl;
    }
  }
  if( DEBUG ) {
    std::cerr << "--------|--------|-------- CIPHERTEXT --------|--------|--------" << std::endl;
  }
} // Closing renderCiphertext()

//-------|---------|---------|---------|---------|---------|
//       GETTERS / SETTERS
//-------|---------|---------|---------|---------|---------|

void sbox2::setSBox1( unsigned char box[16] ) {
	for (int i = 0; i < 16; i ++ ) S1Linear[ i ] = box[ i ];
}

void sbox2::setSBox2( unsigned char box[16] ) {
	for (int i = 0; i < 16; i ++ ) S2Linear[ i ] = box[ i ];
}

// End of file sbox.cpp
