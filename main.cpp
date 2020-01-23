#include "sbox.h"
#include <iostream>
#include <string>
#include <fstream>

#define DEBUG true

int main() {
  if( DEBUG ) {
  	std::cerr << "Generating an sbox instance..." << std::endl << std::endl;
  }
  sbox theBox;
  theBox.renderPlaintext( 40 );

  // Test Sbox load
  theBox.loadSbox( "S1.txt", "S2.txt" );

  // Test key load
  theBox.loadKeys( "keys.txt" );

  // Test text load
  theBox.loadPlaintext( "plaintext.txt" );

  theBox.renderPlaintext( 44 );

  // Test S-box encryption using K1 (rather than K2)
  // Key 1, Row 0
  for( int i = 0 ; i < 11 ; i++ ) {
    theBox.encrypt( "K1", i );
  }

  theBox.renderCiphertext( 44 );

  sbox compareBox;
  compareBox.loadSbox( "S1.txt", "S2.txt" );
  compareBox.loadKeys( "keys.txt" );
  compareBox.loadPlaintext( "plaintext_1bit.txt" );
  for( int i = 0 ; i < 11 ; i++ ) {
    compareBox.encrypt( "K1", i );
  }
  compareBox.renderCiphertext( 44 );

  std::cerr << compareBox.cipherToString( 1, 10) << std::endl;
  compareBox.renderBinaryString( compareBox.cipherToString(1, 10) );

  std::cerr << theBox.avalancheCompare( "abcdeg", "abceeg" ) << std::endl << std::endl;

  std::cerr << theBox.avalancheCompare( theBox.cipherToString( 1, 10), compareBox.cipherToString( 1, 10) ) << std::endl;

  return 1;
}