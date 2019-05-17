
/**
 * File: AESdecrypt.java
 * Author: Brandi Coon
 * Course: MSCS 630
 * Assignment: Project
 * Due Date: May 12, 2019
 * Version: 1.0
 * 
 * This file contains the code to implement
 *  an AES decryption.
 */

/**
 * AESdecrypt
 * 
 * This class contains a few methods, all of which
 *  help to perform AES decryption.
 * 
 */

public class AESdecrypt {
  
  // constant to hold the SBox MATRIX
  public static final String[][] sBox = {
      {"63", "7C", "77", "7B", "F2", "6B", "6F", "C5", "30", "01", "67", "2B", "FE", "D7", "AB", "76"},
      {"CA", "82", "C9", "7D", "FA", "59", "47", "F0", "AD", "D4", "A2", "AF", "9C", "A4", "72", "C0"},
      {"B7", "FD", "93", "26", "36", "3F", "F7", "CC", "34", "A5", "E5", "F1", "71", "D8", "31", "15"},
      {"04", "C7", "23", "C3", "18", "96", "05", "9A", "07", "12", "80", "E2", "EB", "27", "B2", "75"},
      {"09", "83", "2C", "1A", "1B", "6E", "5A", "A0", "52", "3B", "D6", "B3", "29", "E3", "2F", "84"},
      {"53", "D1", "00", "ED", "20", "FC", "B1", "5B", "6A", "CB", "BE", "39", "4A", "4C", "58", "CF"},
      {"D0", "EF", "AA", "FB", "43", "4D", "33", "85", "45", "F9", "02", "7F", "50", "3C", "9F", "A8"},
      {"51", "A3", "40", "8F", "92", "9D", "38", "F5", "BC", "B6", "DA", "21", "10", "FF", "F3", "D2"},
      {"CD", "0C", "13", "EC", "5F", "97", "44", "17", "C4", "A7", "7E", "3D", "64", "5D", "19", "73"},
      {"60", "81", "4F", "DC", "22", "2A", "90", "88", "46", "EE", "B8", "14", "DE", "5E", "0B", "DB"},
      {"E0", "32", "3A", "0A", "49", "06", "24", "5C", "C2", "D3", "AC", "62", "91", "95", "E4", "79"},
      {"E7", "C8", "37", "6D", "8D", "D5", "4E", "A9", "6C", "56", "F4", "EA", "65", "7A", "AE", "08"},
      {"BA", "78", "25", "2E", "1C", "A6", "B4", "C6", "E8", "DD", "74", "1F", "4B", "BD", "8B", "8A"},
      {"70", "3E", "B5", "66", "48", "03", "F6", "0E", "61", "35", "57", "B9", "86", "C1", "1D", "9E"},
      {"E1", "F8", "98", "11", "69", "D9", "8E", "94", "9B", "1E", "87", "E9", "CE", "55", "28", "DF"},
      {"8C", "A1", "89", "0D", "BF", "E6", "42", "68", "41", "99", "2D", "0F", "B0", "54", "BB", "16"}};
  
  // constant to hold the inverse SBox MATRIX
  public static final String[][] inverseSbox = {{"52", "09", "6A", "D5", "30", "36", "A5", "38", "BF", "40", "A3", "9E", "81", "F3", "D7", "FB"},
      {"7C", "E3", "39", "82", "9B", "2F", "FF", "87", "34", "8E", "43", "44", "C4", "DE", "E9", "CB"},
      {"54", "7B", "94", "32", "A6", "C2", "23", "3D", "EE", "4C", "95", "0B", "42", "FA", "C3", "4E"},
      {"08", "2E", "A1", "66", "28", "D9", "24", "B2", "76", "5B", "A2", "49", "6D", "8B", "D1", "25"},
      {"72", "F8", "F6", "64", "86", "68", "98", "16", "D4", "A4", "5C", "CC", "5D", "65", "B6", "92"},
      {"6C", "70", "48", "50", "FD", "ED", "B9", "DA", "5E", "15", "46", "57", "A7", "8D", "9D", "84"},
      {"90", "D8", "AB", "00", "8C", "BC", "D3", "0A", "F7", "E4", "58", "05", "B8", "B3", "45", "06"},
      {"D0", "2C", "1E", "8F", "CA", "3F", "0F", "02", "C1", "AF", "BD", "03", "01", "13", "8A", "6B"},
      {"3A", "91", "11", "41", "4F", "67", "DC", "EA", "97", "F2", "CF", "CE", "F0", "B4", "E6", "73"},
      {"96", "AC", "74", "22", "E7", "AD", "35", "85", "E2", "F9", "37", "E8", "1C", "75", "DF", "6E"},
      {"47", "F1", "1A", "71", "1D", "29", "C5", "89", "6F", "B7", "62", "0E", "AA", "18", "BE", "1B"},
      {"FC", "56", "3E", "4B", "C6", "D2", "79", "20", "9A", "DB", "C0", "FE", "78", "CD", "5A", "F4"},
      {"1F", "DD", "A8", "33", "88", "07", "C7", "31", "B1", "12", "10", "59", "27", "80", "EC", "5F"},
      {"60", "51", "7F", "A9", "19", "B5", "4A", "0D", "2D", "E5", "7A", "9F", "93", "C9", "9C", "EF"},
      {"A0", "E0", "3B", "4D", "AE", "2A", "F5", "B0", "C8", "EB", "BB", "3C", "83", "53", "99", "61"},
      {"17", "2B", "04", "7E", "BA", "77", "D6", "26", "E1", "69", "14", "63", "55", "21", "0C", "7D"}};

  
  // constant to hold the Rcon ARRAY  (0-15 rounds in first "row")
  public static final String[] rcon = { "8D", "01",  "02",  "04",  "08",  "10",  "20",  "40",  "80",  "1B",  "36",  "6C",  "D8",  "AB",  "4D",  "9A",
       "2F",  "5E",  "BC",  "63",  "C6",  "97",  "35",  "6A",  "D4",  "B3",  "7D",  "FA",  "EF",  "C5",  "91",  "39",
       "72",  "E4",  "D3",  "BD",  "61",  "C2",  "9F",  "25",  "4A",  "94",  "33",  "66",  "CC",  "83",  "1D",  "3A",
       "74",  "E8",  "CB",  "8D",  "01",  "02",  "04",  "08",  "10",  "20", "40",  "80",  "1B",  "36",  "6C",  "D8",
       "AB",  "4D",  "9A",  "2F",  "5E",  "BC", "63",  "C6",  "97",  "35",  "6A",  "D4",  "B3",  "7D",  "FA",  "EF",
       "C5",  "91",  "39",  "72",  "E4",  "D3",  "BD",  "61",  "C2",  "9F",  "25",  "4A",  "94",  "33",  "66",  "CC",
       "83",  "1D",  "3A",  "74",  "E8",  "CB",  "8D",  "01",  "02",  "04",  "08",  "10",  "20",  "40",  "80",  "1B",
       "36",  "6C",  "D8",  "AB",  "4D",  "9A",  "2F",  "5E",  "BC",  "63",  "C6",  "97",  "35",  "6A",  "D4",  "B3",
       "7D",  "FA",  "EF",  "C5",  "91",  "39",  "72",  "E4",  "D3",  "BD",  "61",  "C2",  "9F",  "25",  "4A",  "94",
       "33",  "66",  "CC",  "83",  "1D",  "3A",  "74",  "E8",  "CB",  "8D",  "01",  "02",  "04",  "08",  "10",  "20",
       "40",  "80",  "1B",  "36",  "6C",  "D8",  "AB",  "4D",  "9A",  "2F",  "5E",  "BC",  "63",  "C6",  "97",  "35",
       "6A",  "D4",  "B3",  "7D",  "FA",  "EF",  "C5",  "91",  "39",  "72",  "E4",  "D3",  "BD",  "61",  "C2",  "9F",
       "25",  "4A",  "94",  "33",  "66",  "CC",  "83",  "1D",  "3A",  "74",  "E8",  "CB",  "8D",  "01", "02",  "04",
       "08",  "10",  "20",  "40",  "80",  "1B",  "36",  "6C",  "D8",  "AB",  "4D",  "9A",  "2F",  "5E",  "BC",  "63",
       "C6",  "97",  "35",  "6A",  "D4",  "B3",  "7D",  "FA",  "EF",  "C5",  "91",  "39",  "72",  "E4",  "D3",  "BD",
       "61",  "C2",  "9F",  "25",  "4A",  "94",  "33",  "66",  "CC",  "83",  "1D",  "3A",  "74",  "E8",  "CB"};
  
  // Inverse Galois matrix
  public static final String[][] invgalois = {{"0E", "0B", "0D", "09"},
      {"09", "0E", "0B", "0D"},
      {"0D", "09", "0E", "0B"},
      {"0B", "0D", "09", "0E"}};
  
  /*
   * Look up tables used for inverse MixColumns that were found on the Rijndael MixColumns Wikipedia Page.
   * Each table is used based on what a certain number is multiplied by (i.e. If some number 'a' is multiplied by 3, use the mc3 table.)
   */
  
  public static final String[][] mc9 = {   {"00","09","12","1B","24","2D","36","3F","48","41","5A","53","6C","65","7E","77"},
      {"90","99","82","8B","B4","BD","A6","AF","D8","D1","CA","C3","FC","F5","EE","E7"},
      {"3B","32","29","20","1F","16","0D","04","73","7A","61","68","57","5E","45","4C"},
      {"AB","A2","B9","B0","8F","86","9D","94","E3","EA","F1","F8","C7","CE","D5","DC"},
      {"76","7F","64","6D","52","5B","40","49","3E","37","2C","25","1A","13","08","01"},
      {"E6","EF","F4","FD","C2","CB","D0","D9","AE","A7","BC","B5","8A","83","98","91"},
      {"4D","44","5F","56","69","60","7B","72","05","0C","17","1E","21","28","33","3A"},
      {"DD","D4","CF","C6","F9","F0","EB","E2","95","9C","87","8E","B1","B8","A3","AA"},
      {"EC","E5","FE","F7","C8","C1","DA","D3","A4","AD","B6","BF","80","89","92","9B"},
      {"7C","75","6E","67","58","51","4A","43","34","3D","26","2F","10","19","02","0B"},
      {"D7","DE","C5","CC","F3","FA","E1","E8","9F","96","8D","84","BB","B2","A9","A0"},
      {"47","4E","55","5C","63","6A","71","78","0F","06","1D","14","2B","22","39","30"},
      {"9A","93","88","81","BE","B7","AC","A5","D2","DB","C0","C9","F6","FF","E4","ED"},
      {"0A","03","18","11","2E","27","3C","35","42","4B","50","59","66","6F","74","7D"},
      {"A1","A8","B3","BA","85","8C","97","9E","E9","E0","FB","F2","CD","C4","DF","D6"},
      {"31","38","23","2A","15","1C","07","0E","79","70","6B","62","5D","54","4F","46"}};

public static final String[][] mc11 = {  {"00","0B","16","1D","2C","27","3A","31","58","53","4E","45","74","7F","62","69"},
      {"B0","BB","A6","AD","9C","97","8A","81","E8","E3","FE","F5","C4","CF","D2","D9"},
      {"7B", "70", "6D", "66", "57", "5C", "41", "4A", "23", "28", "35", "3E", "0F", "04", "19", "12"},
      {"CB","C0","DD","D6","E7","EC","F1","FA","93","98","85","8E","BF","B4","A9","A2"},
      {"F6","FD","E0","EB","DA","D1","CC","C7","AE","A5","B8","B3","82","89","94","9F"},
      {"46","4D","50","5B","6A","61","7C","77","1E","15","08","03","32","39","24","2F"},
      {"8D","86","9B","90","A1","AA","B7","BC","D5","DE","C3","C8","F9","F2","EF","E4"},
      {"3D","36","2B","20","11","1A","07","0C","65","6E","73","78","49","42","5F","54"},
      {"F7","FC","E1","EA","DB","D0","CD","C6","AF","A4","B9","B2","83","88","95","9E"},
      {"47","4C","51","5A","6B","60","7D","76","1F","14","09","02","33","38","25","2E"},
      {"8C","87","9A","91","A0","AB","B6","BD","D4","DF","C2","C9","F8","F3","EE","E5"},
      {"3C","37","2A","21","10","1B","06","0D","64","6F","72","79","48","43","5E","55"},
      {"01","0A","17","1C","2D","26","3B","30","59","52","4F","44","75","7E","63","68"},
      {"B1","BA","A7","AC","9D","96","8B","80","E9","E2","FF","F4","C5","CE","D3","D8"},
      {"7A","71","6C","67","56","5D","40","4B","22","29","34","3F","0E","05","18","13"},
      {"CA","C1","DC","D7","E6","ED","F0","FB","92","99","84","8F","BE","B5","A8","A3"}};

public static final String[][] mc13 = {  {"00","0D","1A","17","34","39","2E","23","68","65","72","7F","5C","51","46","4B"},
      {"D0","DD","CA","C7","E4","E9","FE","F3","B8","B5","A2","AF","8C","81","96","9B"},
      {"BB","B6","A1","AC","8F","82","95","98","D3","DE","C9","C4","E7","EA","FD","F0"},
      {"6B","66","71","7C","5F","52","45","48","03","0E","19","14","37","3A","2D","20"},
      {"6D","60","77","7A","59","54","43","4E","05","08","1F","12","31","3C","2B","26"},
      {"BD","B0","A7","AA","89","84","93","9E","D5","D8","CF","C2","E1","EC","FB","F6"},
      {"D6","DB","CC","C1","E2","EF","F8","F5","BE","B3","A4","A9","8A","87","90","9D"},
      {"06","0B","1C","11","32","3F","28","25","6E","63","74","79","5A","57","40","4D"},
      {"DA","D7","C0","CD","EE","E3","F4","F9","B2","BF","A8","A5","86","8B","9C","91"},
      {"0A","07","10","1D","3E","33","24","29","62","6F","78","75","56","5B","4C","41"},
      {"61","6C","7B","76","55","58","4F","42","09","04","13","1E","3D","30","27","2A"},
      {"B1","BC","AB","A6","85","88","9F","92","D9","D4","C3","CE","ED","E0","F7","FA"},
      {"B7","BA","AD","A0","83","8E","99","94","DF","D2","C5","C8","EB","E6","F1","FC"},
      {"67","6A","7D","70","53","5E","49","44","0F","02","15","18","3B","36","21","2C"},
      {"0C","01","16","1B","38","35","22","2F","64","69","7E","73","50","5D","4A","47"},
      {"DC","D1","C6","CB","E8","E5","F2","FF","B4","B9","AE","A3","80","8D","9A","97"}};

public static final String[][] mc14 = {  {"00","0E","1C","12","38","36","24","2A","70","7E","6C","62","48","46","54","5A"},
      {"E0","EE","FC","F2","D8","D6","C4","CA","90","9E","8C","82","A8","A6","B4","BA"},
      {"DB","D5","C7","C9","E3","ED","FF","F1","AB","A5","B7","B9","93","9D","8F","81"},
      {"3B","35","27","29","03","0D","1F","11","4B","45","57","59","73","7D","6F","61"},
      {"AD","A3","B1","BF","95","9B","89","87","DD","D3","C1","CF","E5","EB","F9","F7"},
      {"4D","43","51","5F","75","7B","69","67","3D","33","21","2F","05","0B","19","17"},
      {"76","78","6A","64","4E","40","52","5C","06","08","1A","14","3E","30","22","2C"},
      {"96","98","8A","84","AE","A0","B2","BC","E6","E8","FA","F4","DE","D0","C2","CC"},
      {"41","4F","5D","53","79","77","65","6B","31","3F","2D","23","09","07","15","1B"},
      {"A1","AF","BD","B3","99","97","85","8B","D1","DF","CD","C3","E9","E7","F5","FB"},
      {"9A","94","86","88","A2","AC","BE","B0","EA","E4","F6","F8","D2","DC","CE","C0"},
      {"7A","74","66","68","42","4C","5E","50","0A","04","16","18","32","3C","2E","20"},
      {"EC","E2","F0","FE","D4","DA","C8","C6","9C","92","80","8E","A4","AA","B8","B6"},
      {"0C","02","10","1E","34","3A","28","26","7C","72","60","6E","44","4A","58","56"},
      {"37","39","2B","25","0F","01","13","1D","47","49","5B","55","7F","71","63","6D"},
      {"D7","D9","CB","C5","EF","E1","F3","FD","A7","A9","BB","B5","9F","91","83","8D"}};
 
  
/**
 * aesRoundKeys
 *
 * This function produces 11 round keys for the AES Cipher
 * 
 * Parameters:
 *   String keyHex: a length 16-hex string representation of the system key Ke
 * 
 * Return value (roundKeysHex): an 11-row string array representation of all the round keys.
 *  Each element of roundKeysHex will contain a 16-hex string corresponding to each round key
 */
public static String[] aesRoundKeys(String keyHex) {
  
  // The Ke matrix, W matrix, and solution matrix
  String[][] kMatrix = new String [4][4];
  String [][] wMatrix = new String [4][44];
  String[] roundKeysHex = {"", "", "", "", "", "", "", "", "", "", ""};
  
  // Variables to keep track of the current round and current
  // column index we are operating on
  double round = 0;
  int colIndex = 0;
  
  String [] keyHexArr = keyHex.split("(?<=\\G..)");
  
  // Add the keyHex input to the 4x4 Ke matrix
  int m = 0;
  for(int i = 0; i < 4; i++) {
    
    for(int j = 0; j < 4; j ++) {
      
      kMatrix[j][i] = keyHexArr[m];
      m++;
      
    }
    
  }
  
  // Put the key into the first four columns of the 4x44 W matrix
  for(int i = 0; i < 4; i++) {
    
    for(int j = 0; j < 4; j++) {
      
      wMatrix[i][j] = kMatrix[i][j];
      
    }
    
  }
  
  // We should now be at round 1 (round 0 was filling the key into
  // the first four columns), and we filled in columns 0-3 so we should
  // now be working on 4 and up
  round = 1;
  colIndex = 4;
  
  // Calculate the rest of the 40 columns in the W matrix
  while(round < 11.0 && colIndex < 44) {
    
    round = Math.floor(colIndex/4);
    
    // If it is a multiple of 4...
    // else if it is not a multiple of 4...
    if(colIndex % 4 == 0) {
      
      String[] wNew = new String[4];
      
      for(int i = 0; i < 4; i++) {
        wNew[i] = wMatrix[i][colIndex - 1]; 
      }
      
      // Shift the values left
      wNew = shiftLeft(wNew);
      
      // Use S-Box function to transform each of the four bytes
      for(int i = 0; i < 4; i++) {
        wNew[i] = aesSBox(wNew[i]);
      }
      
      // Get Rcon(i) constant for the ith round
      String rConConst = aesRcon((int)round);
      
      // XOR the columns
      String newEl = xorHex(rConConst,wNew[0]);
      
      wNew[0] = newEl;
      
      String [] jMin4Col = new String[4];
      // Retrieve the values from the two columns that will need the XOR operation
      for(int i = 0; i < 4; i++) {
        
        jMin4Col[i] = wMatrix[i][colIndex - 4];
        
      }
      
      String s1 = "";
      String s2 = "";
      
      for(int i = 0; i < 4; i ++) {
        
        s1 = s1 + jMin4Col[i];
        s2 = s2 + wNew[i];
        
      }
      
      // XOR the columns
      String newCol = xorHex(s1,s2);
      String [] newColArr = newCol.split("(?<=\\G..)");
      
      
      // Put the newly generated column into the 4x44 W matrix
      for(int i = 0; i < 4; i++) {
          
          wMatrix[i][colIndex] = newColArr[i];
          
      }
      
    } else {
      
      // Columns for the values to be XORed
      String [] jMin4Col = new String[4];
      String [] jMin1Col = new String[4];
      
      // Retrieve the values from the two columns that will need the XOR operation
      for(int i = 0; i < 4; i++) {
        
        jMin4Col[i] = wMatrix[i][colIndex - 4];
        jMin1Col[i] = wMatrix[i][colIndex - 1];
        
      }
      
      String s1 = "";
      String s2 = "";
      
      for(int i = 0; i < 4; i ++) {
        
        s1 = s1 + jMin4Col[i];
        s2 = s2 + jMin1Col[i];
        
      }
      
      // XOR the columns
      String newCol = xorHex(s1,s2);
      String [] newColArr = newCol.split("(?<=\\G..)");
      
      // Put the XORed values into the newly generated column of the 4x44 W matrix
      for(int i = 0; i < 4; i++) {
        
            wMatrix[i][colIndex] = newColArr[i];
          
      }
      
    }
    
    colIndex++;
    
  }
  
  
  // Add the wMatrix into an Array of size 11 (for 11 rounds)
  int k = 0;
  int l = 0;
  for(int i = 0; i < 11; i++) {
    for(int j = 0; j < 16; j++) {
      roundKeysHex[i] = roundKeysHex[i] + wMatrix[k][l];
      k++;
      if(k >= 4) {
        k = 0;
        l ++;
      } 
    }
  }
  
  return roundKeysHex;
  
}

/**
 * aesSBox
 *
 * This function reads the SBox given a hexadecimal number
 * 
 * Parameters:
 *   String inHex: the given hexadecimal value used to read a new
 *   hex value from the table
 * 
 * Return value(outHex): the hexadecimal value obtained from the SBox
 */
public static String aesSBox(String inHex) {
  
  // Convert the hex string into a decimal number
  int intInHex = Integer.parseInt(inHex, 16);
  
  // For the row column use the division operator by 16
  // (because we're dealing with hex numbers), and for the
  // column number use modulo to find the remainder
  String outHex = sBox[intInHex / 16][intInHex % 16];
  
  return outHex;
  
}

  /**
   * aesInverseSBox
   *
   * This function reads the inverse SBox given a hexadecimal number
   * 
   * Parameters:
   *   String inHex: the given hexadecimal value used to read a new
   *   hex value from the table
   * 
   * Return value(outHex): the hexadecimal value obtained from the inverse SBox
   */
  public static String aesInverseSBox(String inHex) {
    
    // Convert the hex string into a decimal number
    int intInHex = Integer.parseInt(inHex, 16);
    
    // For the row column use the division operator by 16
    // (because we're dealing with hex numbers), and for the
    // column number use modulo to find the remainder
    String outHex = inverseSbox[intInHex / 16][intInHex % 16];
    
    return outHex;
    
  }
  
  /**
   * aesRcon
   *
   * This function gets each round's constant
   * 
   * Parameters:
   *   int round: the current round number
   * 
   * Return value(outHex): the value obtained from the Rcon table
   */
  public static String aesRcon(int round) {
    
    return rcon[round];
    
  }
  
  /**
   * AESStateXOR
   *
   * This is a method for "AES Add Key". The inputs and outputs
   *  of this method are both four by four matrices where every element
   *  is a pair of hex digits and will perform the “Add Round Key” operation
   *  (that is, the entries of the output matrix are simply the XOR of the
   *  corresponding input matrix entries).
   * 
   * Parameters:
   *   String sHex: the four by four input string hex matrix
   *   String keyHex: the four by four key matrix
   * 
   * Return value(outStateHex): the result of the XOR of the input matrices
   */
  public static String AESStateXOR(String sHex, String keyHex) {
    
    // XOR the two input matrices
    String outStateHex = xorHex(sHex, keyHex);
    
    return outStateHex;
  }
  
  /**
   * AESInverseNibbleSub
   *
   * This method’s input and output are supposed four by four matrices of pairs of hex digits
   * (I have them in an array format of 16 values of hex digits for now until I convert it later).
   * The method will perform the inverse “Substitution” operation (the entries of the output matrix
   * result from running the corresponding input matrix entries through the inverse AES SBox)
   * 
   * Parameters:
   *   String inStateHex: a four by four matrix of pairs of Hex digits
   * 
   * Return value(outStateHex): an array with 16 values of hex digits (which is really the 4x4 matrix
   * just in a different format) that is the result of running the input array (the supposed 4x4 matrix)
   * through the inverse AES SBox
   */
  public static String[] AESInverseNibbleSub(String inStateHex) {
    
    // Split the given string into an array with two hex digits in each spot
    String [] arr = inStateHex.split("(?<=\\G..)");
    
    // Perform the SBox substitution on each element in the array
    for(int i = 0; i < arr.length; i++) {
      arr[i] = aesInverseSBox(arr[i]);
    }
    
    return arr;
  }
  
  /**
   * AESInverseShiftRow
   *
   * This function's inputs and output are 4 by 4 matrices of pairs of hex digits
   * and will perform the inverse "Shift Row" operation of the AES to transform the input
   * state matrix into output state (the input is an array of 16 hex values)
   * 
   * Parameters:
   *   String inStateHex: the four by four input matrix to be shifted (array of 16 values)
   * 
   * Return value(outStateHex): the four by four matrix after being inversely shifted
   */
  public static String[][] AESInverseShiftRow(String[] inStateHex) {
    
    String[][] m = new String[4][4];
    
    // Make it into a matrix
    int k = 0;
    for(int i = 0; i < 4; i++) {
      for(int j = 0; j < 4; j++) {
        m[j][i] = inStateHex[k];
        k++;
      }
    }
    
    // Shift the rows (row 0 remains unchanged, row 1 shifted one to the right,
    // row 2 shifted two to the right, and row 3 shifted three to the right)
    String[] shifted = new String[4];
    
    // row 1
    // Shift it once
    shifted = shiftRight(m[1]);
    
    // Put it back into the matrix
    for(int o = 0; o < 4; o++) {
      m[1][o] = shifted[o];
    }
    
    // row 2
    shifted = shiftRight(m[2]);
    shifted = shiftRight(shifted);
    
    for(int i = 0; i < 4; i++) {
      m[2][i] = shifted[i];
    }
    
    // row 3
    shifted = shiftRight(m[3]);
    shifted = shiftRight(shifted);
    shifted = shiftRight(shifted);
    
    for(int o = 0; o < 4; o++) {
      m[3][o] = shifted[o];
    }
    
    return m;
  }
  
  /**
   * AESInverseMixColumn
   *
   * This function's input and output are 4 by 4 matrices of pairs of hex digits and
   * will perform the inverse Mix Column operation of AES to transform the input state into output
   * state. This function is  performed by mapping each element in the current matrix with the value
   * returned by its helper function.
   * 
   * Parameters:
   *   String inStateHex: four by four matrix to be operated on
   * 
   * Return value(outStateHex): four by four matrix after inverse Mix Column operation
   */
  public static String[][] AESInverseMixColumn(String[][] inStateHex) {
    
    String[][] tempArray = new String[4][4];
    
    // Copy the elements of the matrix over to the temp matrix
    for(int i = 0; i < 4; i++){
        System.arraycopy(inStateHex[i], 0, tempArray[i], 0, 4);
    }
    
    for (int i = 0; i < 4; i++) {
      for (int j = 0; j < 4; j++) {
          inStateHex[j][i] = mcInverseHelper(tempArray, invgalois, i, j);
      }
    }
    
    return inStateHex;
  }

  /**
   * mcInverseHelper
   *
   * inverse Helper method of mixColumns to use the mix columns formula on each element
   * 
   * Parameters:
   *   String[][] arr: the current matrix being checked
   *   String g: the inverse galois matrix
   *   int i: row position
   *   int j: column position
   * 
   * Return value: computed inverse mix columns value
   */
  public static String mcInverseHelper(String[][] arr, String[][] g, int i, int j){
      
    String mcsum = "00";
      for (int k = 0; k < 4; k++) {
          int a = Integer.parseInt(g[i][k], 16);
          int b = Integer.parseInt(arr[k][j], 16);
          mcsum = xorHex(mcsum,mcInverseCalc(a, b, arr[k][j]));
      }
      return mcsum;
  }

  /**
   * mcInverseCalc
   *
   * inverse Helper method used in mcHelper
   * 
   * Parameters:
   *   int a: the inverse galois matrix number
   *   int b: the inStateHex array number
   * 
   * Return value: depending on the galois field number, we output the appropriate values
   */
  public static String mcInverseCalc(int a, int b, String bString){
      
    if (a == 9) {
          return mc9[b / 16][b % 16];
      } else if (a == 0xb) {
          return mc11[b / 16][b % 16];
      } else if (a == 0xd) {
          return mc13[b / 16][b % 16];
      } else if (a == 0xe) {
        return mc14[b / 16][b % 16];
    }
      return "00";
  }
  
  /**
   * AESDecrypt
   *
   * This function will perform the AES decryption following the inverse algorithm
   * shown in Figure 1 of the Lab 5 description (using the Add Key, Nibble Substitution,
   * Shift Rows, and Mix Columns operations).
   * 
   * Parameters:
   *   String encryptedString: the input hex string of encryption to be decrypted
   *   String keyHex: the input hex key
   * 
   * Return value(cTextHex): the output plain-text in hex
   */
  public static String AESDecrypt(String encryptedString, String keyHex) {
    
    String outStateHex;
    String[] outHex;
    String[][] outMatrixHex = new String[4][4];
    
    // Generate the round keys
    String[] roundKeysHex = aesRoundKeys(keyHex);
    
    // Perform the first Add Key operation
    outStateHex = AESStateXOR(encryptedString, roundKeysHex[10]);
    
    outHex = outStateHex.split("(?<=\\G..)");
    
    // Loop through the shift rows, nibble substitution, mix columns,
    // and add key methods until we reach the last round (i.e. round 0
    // from rounds 9 to 1)
    for(int k = 9; k > 0; k--) {
      
      if(k < 9) {
        
        StringBuilder sb5 = new StringBuilder();
        for(int i = 0; i < 4; i++) {
            for(int j = 0; j < 4; j++) {
              sb5.append(outMatrixHex[i][j]);
            }
        }
        outStateHex = sb5.toString();
        
        // Make the outStateHex into a 4x4 array
        outHex = outStateHex.split("(?<=\\G..)");
        
      }
      // Inverse shift row
      outMatrixHex = AESInverseShiftRow(outHex);
      
      // Make the array into string form for the next function
      StringBuilder sb1 = new StringBuilder();
      for(int i = 0; i < 4; i++) {
          for(int j = 0; j < 4; j++) {
            sb1.append(outMatrixHex[j][i]);
          }
      }
      outStateHex = sb1.toString();
      
      // Inverse nibble substitution
      outHex = AESInverseNibbleSub(outStateHex);
      
      StringBuilder sb2 = new StringBuilder();
      for(int i = 0; i < 16; i++) {
            sb2.append(outHex[i]);
      }
      outStateHex = sb2.toString();
      outStateHex = AESStateXOR(outStateHex, roundKeysHex[k]);
      
      // Make the outStateHex into a 4x4 array
      outHex = outStateHex.split("(?<=\\G..)");
      
      // Add to the 4x4 matrix
      int m = 0;
      for(int i = 0; i < 4; i++) {
        
        for(int j = 0; j < 4; j ++) {
          
          outMatrixHex[j][i] = outHex[m];
          m++;
          
        }
        
      }
      
      // Inverse mix column
      outMatrixHex = AESInverseMixColumn(outMatrixHex);
      
    }
    
    // Make the array into string form for the next function
    StringBuilder sb3 = new StringBuilder();
    for(int i = 0; i < 4; i++) {
        for(int j = 0; j < 4; j++) {
          sb3.append(outMatrixHex[i][j]);
        }
    }
    outStateHex = sb3.toString();
    
    // Make the outStateHex into a 4x4 array
    outHex = outStateHex.split("(?<=\\G..)");
    
    // Inverse shift row
    outMatrixHex = AESInverseShiftRow(outHex);
    
    // Make the array into string form for the next function
    StringBuilder sb4 = new StringBuilder();
    for(int i = 0; i < 4; i++) {
        for(int j = 0; j < 4; j++) {
          sb4.append(outMatrixHex[j][i]);
        }
    }
    outStateHex = sb4.toString();
    
    // Inverse nibble substitution
    outHex = AESInverseNibbleSub(outStateHex);
    
    StringBuilder sb6 = new StringBuilder();
    for(int i = 0; i < 16; i++) {
          sb6.append(outHex[i]);
    }
    outStateHex = sb6.toString();
    
    outStateHex = AESStateXOR(outStateHex, roundKeysHex[0]);
    
    return outStateHex;
  }
  
  /**
   * shiftLeft
   *
   * This function shifts an array's values
   * one spot to the left
   * 
   * Parameters:
   *   int[] shiftArray: the array whose values we will be shifting
   * 
   * Return value: the newly left-shifted array
   */
  public static String[] shiftLeft(String[] shiftArray) {
    
    // store the first value in the array
    String temp = shiftArray[0];
    
    // iterate through the array and assign the new
    // shifted values
    for (int i = 0; i < shiftArray.length - 1; i++) {
      
        shiftArray[i] = shiftArray[i + 1];
        
    }
    
    // put the first value in the last spot
    shiftArray[shiftArray.length - 1] = temp;
    
    return shiftArray;
    
  }
  
  
  /**
   * shiftRight
   *
   * This function shifts an array's values
   * one spot to the right
   * 
   * Parameters:
   *   int[] shiftArray: the array whose values we will be shifting
   * 
   * Return value: the newly right-shifted array
   */
  public static String[] shiftRight(String[] shiftArray) {
    
    // store the last value in the array
    String temp = shiftArray[shiftArray.length - 1];
    
    // iterate through the array and assign the new
    // shifted values
    for (int i = shiftArray.length - 1; i > 0; i--) {
      
        shiftArray[i] = shiftArray[i - 1];
        
    }
    
    shiftArray[0] = temp;
    
    return shiftArray;
    
  }
  
  /*
   * xorHex
   *
   * This function xors two hex values
   * 
   * Parameters:
   *   String a: first string in the xor computation
   *   String b: second string in the xor computation
   * 
   * Return value: the result of the xor computation
   */
  public static String xorHex(String a, String b) {
    
    char[] characters = new char[a.length()];
    
    for (int i = 0; i < characters.length; i++) {
      
        characters[i] = toHex(fromHex(a.charAt(i)) ^ fromHex(b.charAt(i)));
        
    }
    return new String(characters);
  }

  /*
   * fromHex
   *
   * This function converts FROM hex values
   * 
   * Parameters:
   *   char c: character to be converted
   * 
   * Return value: converted value FROM hex
   */
  public static int fromHex(char c) {
    
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    throw new IllegalArgumentException();
    
  }

  /*
   * toHex
   *
   * This function converts TO a hex value
   * 
   * Parameters:
   *   int nibble: index of the hex value
   * 
   * Return value: the TO hex value conversion
   */
  public static char toHex(int nibble) {
    
    if (nibble < 0 || nibble > 15) {
        throw new IllegalArgumentException();
    }
    
    return "0123456789ABCDEF".charAt(nibble);
  }

  
}
