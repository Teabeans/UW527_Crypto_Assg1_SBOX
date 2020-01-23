#pragma once

#include <iostream>
#include <string>
#include <fstream>

#define MAX_MSG_LENGTH 1024

class sbox {
  public:
  // Substitution boxes
  unsigned char S1[4][4]; // [row][col]
  unsigned char S1Linear[16];
  unsigned char S2[4][4]; // [row][col]
  unsigned char S2Linear[16];

  // Keys
  unsigned char K1[4];
  unsigned char K2[4];

  // Plaintext and ciphertext buffers
  unsigned char plaintext[ MAX_MSG_LENGTH ];
  unsigned char ciphertext[ MAX_MSG_LENGTH ];

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

  // Convert data from one to another
  int convertBinaryToInt( std::string binaryString );
  char convertIntToChar( int input );

  // Convert a row selection to string
  std::string cipherToString( int min, int max );

  // Render texts
  void renderBinaryString( std::string bitSequence );
  void renderPlaintext( int length );
  void renderCiphertext( int length );


  // Getters/Setters
  unsigned char getBoxValue( int boxNumber, int position );
};

