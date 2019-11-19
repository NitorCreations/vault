package com.nitorcreations.vault2;


public class VaultException extends RuntimeException {
  public VaultException(String message, Exception cause) {
    super(message, cause);
  }
}
