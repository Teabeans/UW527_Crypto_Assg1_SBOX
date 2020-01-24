#pragma once

//-------|---------|---------|---------|---------|---------|---------|---------|
//
// UW CSS 527 - Assg1 - Substitution Boxes
// sbox.h
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
// Declaration file for the sbox class

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

#define MAX_MSG_LENGTH 1024

//-------|---------|---------|---------|---------|---------|---------|---------|
//
//       INCLUDES
//
//-------|---------|---------|---------|---------|---------|---------|---------|

#include <iostream>
#include <string>
#include <fstream>

class sbox {
  public:

//-------|---------|---------|---------|---------|---------|---------|---------|
//
//       PUBLIC FIELDS
//
//-------|---------|---------|---------|---------|---------|---------|---------|

  // Substitution boxes (as grid)
  unsigned char S1[4][4]; // [row][col]
  unsigned char S2[4][4]; // [row][col]
  // Substitution boxes (linear)
  unsigned char S1Linear[16];
  unsigned char S2Linear[16];

  // Keys
  unsigned char K1[4];
  unsigned char K2[4];

  // Plaintext and ciphertext buffers
  unsigned char plaintext[  MAX_MSG_LENGTH ];
  unsigned char ciphertext[ MAX_MSG_LENGTH ];

//-------|---------|---------|---------|---------|---------|---------|---------|
//
//       PUBLIC METHODS
//
//-------|---------|---------|---------|---------|---------|---------|---------|

  // Constructor/Destructors
  sbox();
  ~sbox();

  // Scrubber
  void tareFields();

  // Loaders
  bool loadPlaintext( std::string filename );
  bool loadSbox( std::string filenameS1, std::string filenameS2 );
  bool loadKeys( std::string filename );

  // Workers
  void encrypt( std::string keyDesignate, int row );
  double avalancheCompare( std::string seq1, std::string seq2 );

  // Converters
  int convertBinaryToInt( std::string binaryString );
  char convertIntToChar( int input );

  // toStrings
  std::string cipherToString( int min, int max );

  // Renderers
  void renderBinaryString( std::string bitSequence );
  void renderPlaintext( int length );
  void renderCiphertext( int length );

  // Getters/Setters
  unsigned char getBoxValue( int boxNumber, int position );
}; // Closing class sbox

// End of file sbox.h
