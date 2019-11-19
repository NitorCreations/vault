package com.nitorcreations.vault;


public class VaultException extends RuntimeException {
  public VaultException(String message, Exception cause) {
    super(message, cause);
  }
}
