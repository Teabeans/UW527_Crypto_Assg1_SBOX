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
// Created:  2020.01.15
// Modified: 2020.--.-- (TODO)
// For the University of Washington Bothell, CSS 527
// Winter 2020, Masters in Cybersecurity Engineering (MCSE)
//

//-----------------------------------------------------------------------------|
// File Description
//-----------------------------------------------------------------------------|
//
// TODO

//-----------------------------------------------------------------------------|
// Package Files
//-----------------------------------------------------------------------------|
//
// TODO

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
#define MAX_MSG_LENGTH 1024

//-------|---------|---------|---------|---------|---------|---------|---------|
//
//       INCLUDES
//
//-------|---------|---------|---------|---------|---------|---------|---------|

#include "sbox.h"

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
// #TODO( )
// ------------------------------------|
// Desc:    TODO
// Params:  TODO
// PreCons: TODO
// PosCons: TODO
// RetVal:  TODO
sbox::sbox( ) {
  this->tareFields();
}

// (+) --------------------------------|
// #TODO( )
// ------------------------------------|
// Desc:    TODO
// Params:  TODO
// PreCons: TODO
// PosCons: TODO
// RetVal:  TODO
sbox::~sbox( ) {
  this->tareFields();
}

// (+) --------------------------------|
// #TODO( )
// ------------------------------------|
// Desc:    TODO
// Params:  TODO
// PreCons: TODO
// PosCons: TODO
// RetVal:  TODO
void sbox::tareFields( ) {
  for( int row = 0 ; row < 4 ; row++ ) {
    this->K1[row] = (unsigned char)0;
    this->K2[row] = (unsigned char)0;
    for( int col = 0 ; col < 4 ; col++ ) {
      this->S1[row][col] = (unsigned char)0;
      this->S2[row][col] = (unsigned char)0;
    }
  }
  for( int i = 0 ; i < 16 ; i++ ) {
    this->S1Linear[i] = (unsigned char)0;
    this->S2Linear[i] = (unsigned char)0;
  }
  for( int i = 0 ; i < MAX_MSG_LENGTH ; i++ ) {
    this->plaintext[ i ]  = '\0';
    this->ciphertext[ i ] = '\0';
  }
}

//-------|---------|---------|---------|---------|---------|---------|---------|
//
//       PUBLIC METHOD IMPLEMENTATIONS
//
//-------|---------|---------|---------|---------|---------|---------|---------|

//-------|---------|---------|---------|---------|---------|
//       LOADERS
//-------|---------|---------|---------|---------|---------|

// (+) --------------------------------|
// #loadPlaintext( )
// ------------------------------------|
// Desc:    Reads a file of bits into the plaintext buffer
// Params:  TODO
// PreCons: TODO
// PosCons: TODO
// RetVal:  TODO
bool sbox::loadPlaintext( std::string filename ) {
  if( DEBUG ) {
    std::cerr << "Loading plaintext from '" << filename << "'... ";
  }
  // Load 'filename' to a filestream ('plaintext')
  std::ifstream plaintext;
  plaintext.open( filename );
  std::string nibble;
  int currPos = 0;

  // While there are characters in the filestream...
  while( !plaintext.eof() ) {
    // Snip off a token (4 bits or 1 nibble)
    plaintext >> nibble;
    // Save the nibble as an unsigned char to the plaintext buffer
    this->plaintext[ currPos ] = (unsigned char)std::stoi( nibble, nullptr, 2 );
    // Advance buffer write position by 1
    currPos++;
  }
  // Null terminate the buffer (may by extraneous)
  this->plaintext[ currPos ] = '\0';

  if( DEBUG ) {
    std::cerr << "Plaintext loaded! " << std::endl;
    std::cerr << "  As ints:";
    for( int i = 0 ; i < currPos-1 ; i++ ) {
      // Next set of 4
      if( i % 4 == 0 ) {
        std::cerr << std::endl << "    MSG" << std::setw(3) << (i / 4) << ": [";
      }
      std::cerr << std::setw(3) << (unsigned int)this->plaintext[ i ];
      if( i % 4 != 3 ) {
        std::cerr << ", ";
      }
      if( i % 4 == 3 ) {
        std::cerr << " ]";
      }
    }
    std::cerr << std::endl << std::endl;
  } // Closing debug statement

  return true;
} // Closing sbox::loadPlaintext()

// (+) --------------------------------|
// #loadSbox( )
// ------------------------------------|
// Desc:    Load substitution boxes S1 and S2 from file
// Params:  TODO
// PreCons: TODO
// PosCons: TODO
// RetVal:  TODO
bool sbox::loadSbox( std::string filenameS1, std::string filenameS2 ) {
  if( DEBUG ) {
    std::cerr << "Loading substitution boxes from '" << filenameS1 << "', '" << filenameS2 << "'... ";
  }

  // Load S1
  std::ifstream S1txt;
  S1txt.open( filenameS1 );
  int substitution;
  for( int row = 0 ; row < 4 ; row++ ) {
    for( int col = 0 ; col < 4 ; col++ ) {
      S1txt >> substitution;
      this->S1[row][col]            = (unsigned char)substitution;
      this->S1Linear[((col*4)+row)] = (unsigned char)substitution;
    }
  }
  S1txt.close();

  if( DEBUG ) {
    std::cerr << "S1 loaded! ";
  }

  // Load S2
  std::ifstream S2txt;
  S2txt.open( filenameS2 );
  for( int row = 0 ; row < 4 ; row++ ) {
    for( int col = 0 ; col < 4 ; col++ ) {
      S2txt >> substitution;
      this->S2[row][col]            = (unsigned char)substitution;
      this->S2Linear[((col*4)+row)] = (unsigned char)substitution;
    }
  }
  S2txt.close();

  if( DEBUG ) {
    std::cerr << "S2 loaded!" << std::endl;
  }

  // Check results:
  if( DEBUG ) {
    std::cerr << "Substitution Box S1:" << std::endl;
    std::cerr << "  [ ";
    for( int row = 0 ; row < 4 ; row++ ) {
      for( int col = 0 ; col < 4 ; col++ ) {
        std::cerr << std::setw(3) << (unsigned int)this->S1[row][col] << " ";
        if( row == 3 && col == 3 ) {
          std::cerr << " ]";
        }
      }
      std::cerr << std::endl << "    "; // end of row
    }
    std::cerr << std::endl;

    std::cerr << "Substitution Box S2:" << std::endl;
    std::cerr << "  [ ";
    for( int row = 0 ; row < 4 ; row++ ) {
      for( int col = 0 ; col < 4 ; col++ ) {
        std::cerr << std::setw(3) << (unsigned int)this->S2[row][col] << " ";
        if( row == 3 && col == 3 ) {
          std::cerr << " ]";
        }
      }
      std::cerr << std::endl << "    "; // end of row
    }
    std::cerr << std::endl;

    std::cerr << "SBoxes (Linear):" << std::endl;
    std::cerr << "  Index: [  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 ]" << std::endl;
    std::cerr << "  S1   : ";
    for( int i = 0 ; i < 16 ; i++ ) {
      std::cerr << std::setw(4) << (unsigned int)this->S1Linear[i];
    }
    std::cerr << std::endl;
    std::cerr << "  S2   : ";
    for( int i = 0 ; i < 16 ; i++ ) {
      std::cerr << std::setw(4) << (unsigned int)this->S2Linear[i];
    }
    std::cerr << std::endl << std::endl;
  } // Closing debug results

  return true;
} // Closing loadSbox()

// (+) --------------------------------|
// #loadKeys( )
// ------------------------------------|
// Desc:    TODO
// Params:  TODO
// PreCons: TODO
// PosCons: TODO
// RetVal:  TODO
bool sbox::loadKeys( std::string filename ) {
  if( DEBUG ) {
    std::cerr << "Loading keys K1, K2 from '" << filename << "'..." << std::endl;
  }

  // Load keyfile
  std::ifstream myfile;
  myfile.open( "keys.txt" );
  std::string keyline;

  // Load K1
  for( int i = 0 ; i < 4 ; i++ ) {
    myfile >> keyline;
    K1[i] = (unsigned char)std::stoi( keyline, nullptr, 2 );
  }
  // Load K2
  for( int i = 0 ; i < 4 ; i++ ) {
    myfile >> keyline;
    K2[i] = (unsigned char)std::stoi( keyline, nullptr, 2 );
  }

  if( DEBUG ) {
    std::cerr << "Key K1:" << std::endl;
    for( int i = 0 ; i < 4 ; i++ ) {
      std::cerr << std::setw(3) << (unsigned int)K1[i] << " ";
      if( i == 3 ) {
        std::cerr << std::endl;
      }
    }

    std::cerr << "Key K2:" << std::endl;
    for( int i = 0 ; i < 4 ; i++ ) {
      std::cerr << std::setw(3) << (unsigned int)K2[i] << " ";
      if( i == 3 ) {
        std::cerr << std::endl << std::endl;
      }
    }

  }
  return true;
}

//-------|---------|---------|---------|---------|---------|
//       WORKERS
//-------|---------|---------|---------|---------|---------|

// (+) --------------------------------|
// #encrypt( )
// ------------------------------------|
// Desc:    TODO
// Params:  TODO
// PreCons: TODO
// PosCons: TODO
// RetVal:  TODO
void sbox::encrypt( std::string keyDesignate, int row ) {
  if( DEBUG ) {
    std::cerr << "Encrypting MSG (" << row << ") using '" << keyDesignate << "'..." << std::endl;
  }

  // Transfer the appropriate key into the method
  unsigned char key[4];
  if( keyDesignate == "K1" ) {
    for( int i = 0 ; i < 4 ; i++ ) {
      key[i] = this->K1[i];
    }
  }
  else if( keyDesignate == "K2" ) {
    for( int i = 0 ; i < 4 ; i++ ) {
      key[i] = this->K2[i];
    }
  }
  
  // Copy the row from the plaintext buffer into the method
  unsigned char plaintextRow[4];
  for( int i = 0 ; i < 4 ; i++ ) {
    plaintextRow[i] = this->plaintext[ (row*4) + i];
  }
  
  // Implement the cipher to find the appropriate indices
  unsigned char cipherIndex[4];
  cipherIndex[0] = plaintextRow[1] ^ key[0];
  cipherIndex[1] = plaintextRow[3] ^ key[2];
  cipherIndex[2] = plaintextRow[0] ^ key[1];
  cipherIndex[3] = plaintextRow[2] ^ key[3];

  // Read out from S1 and S2 at the appropriate locations to find the cipher character
  unsigned char cipherRow[4];  
  cipherRow[0] = S1Linear[cipherIndex[0]];
  cipherRow[1] = S2Linear[cipherIndex[1]];
  cipherRow[2] = S1Linear[cipherIndex[2]];
  cipherRow[3] = S2Linear[cipherIndex[3]];

  // Assign the enciphered row to the ciphertext buffer
  for( int i = 0 ; i < 4 ; i++ ) {
    this->ciphertext[i + (row*4)] = cipherRow[i];
  }

  // Report results
  if( DEBUG ) {
    std::cerr << "----- ENCRYPTION COMPLETE -----" << std::endl;
    std::cerr << "  [";
    for( int i = 0 ; i < 4 ; i++ ){
      std::cerr << std::setw(3) << (unsigned int)cipherRow[i];
      if( i % 4 != 3 ) {
        std::cerr << ",";
      }
    }
    std::cerr << " ]" << std::endl << std::endl;
  }

} // Closing encrypt()

// (+) --------------------------------|
// #avalancheCompare( string, string )
// ------------------------------------|
// Desc:    Analyze the avalanche effect
// Params:  TODO
// PreCons: TODO
// PosCons: TODO
// RetVal:  double - The percent from 0.0 to 100.0 from which the strings differs from another sbox
double sbox::avalancheCompare( std::string seq1, std::string seq2 ) {
  if( DEBUG ) {
    std::cerr << "Comparing seq1 (" << seq1.length() << ") against seq2 (" << seq2.length() << ")..." << std::endl;

  }
  if( seq1.length() != seq2.length() ) {
    std::cerr << "Invalid comparison. Sequences are of differing length." << std::endl;
    return 9999.99;
  }

  int diffs = 0;
  for( int i = 0 ; i < seq1.length() ; i++ ) {
    if( seq1.at(i) != seq2.at(i) ) {
      diffs++;
    }
  }

  double retDouble = 100.0 * ((double)diffs / (double)seq1.length());

  return retDouble;  
} // Closing avalancheCompare()

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
int sbox::convertBinaryToInt( std::string binaryString ) {
  unsigned int retval = std::stoi( binaryString, nullptr, 2);
  return retval;
} // Closing convertBinaryToInt()

// (+) --------------------------------|
// #TODO( )
// ------------------------------------|
// Desc:    TODO
// Params:  TODO
// PreCons: TODO
// PosCons: TODO
// RetVal:  TODO
char sbox::convertIntToChar( int input ) {
  char retchar = (char)input;
  return retchar;
}

//-------|---------|---------|---------|---------|---------|
//       RENDERERS
//-------|---------|---------|---------|---------|---------|

// (+) --------------------------------|
// #toString( int, int )
// ------------------------------------|
// Desc:    Convert a selection of rows to their binary representations
// Params:  int arg1 - The first row to convert (inclusive)
//          int arg2 - The final row to convert (inclusive)
// PreCons: TODO
// PosCons: TODO
// RetVal:  TODO
std::string sbox::cipherToString( int minRow, int maxRow ) {
  std::stringstream ss;
  for( int currRow = minRow ; currRow <= maxRow ; currRow++ ) {
    for( int col = 0 ; col < 4 ; col++ ) {
      int currChar = (unsigned int)this->ciphertext[ ((currRow*4) + col) ];
      ss << std::bitset<4>(currChar).to_string();
    }
  }
  return ss.str();
} // closing toString()

void sbox::renderBinaryString( std::string bitSequence ) {
  for( int i = 0 ; i < bitSequence.length() ; i++ ) {
    std::cerr << bitSequence.at(i);
    if( i % 4 == 3 ) {
      std::cerr << " ";
    }
    if( i % 16 == 15 ) {
      std::cerr << std::endl;
    }
  }
}

// (+) --------------------------------|
// #TODO( )
// ------------------------------------|
// Desc:    Renders the Sbox's plaintext buffer
// Params:  TODO
// PreCons: TODO
// PosCons: TODO
// RetVal:  TODO
void sbox::renderPlaintext( int length) {
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
}

// (+) --------------------------------|
// #TODO( )
// ------------------------------------|
// Desc:    Renders the Sbox's ciphertext buffer
// Params:  TODO
// PreCons: TODO
// PosCons: TODO
// RetVal:  TODO
void sbox::renderCiphertext( int length ) {
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
}

//-------|---------|---------|---------|---------|---------|
//       GETTERS / SETTERS
//-------|---------|---------|---------|---------|---------|

// (+) --------------------------------|
// #TODO( )
// ------------------------------------|
// Desc:    Get the value at the supplied linear position within the specified S-Box
// Params:  TODO
// PreCons: TODO
// PosCons: TODO
// RetVal:  TODO
unsigned char sbox::getBoxValue( int boxNumber, int position ) {
/*
  int row = position % MAX_ROWS_COLUMNS;
  int column = position / MAX_ROWS_COLUMNS;

  if ( boxNumber == 1 ) return S1[ row ][ column ];

  return S2[ row ][ column ];
*/
}

// End of file sbox.cpp
