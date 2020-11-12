/*
 * Copyright 2020 ConsenSys AG.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package tech.pegasys.ethsigner.core;

import static org.assertj.core.api.Assertions.assertThat;

import tech.pegasys.signers.secp256k1.EthPublicKeyUtils;
import tech.pegasys.signers.secp256k1.api.Signer;
import tech.pegasys.signers.secp256k1.api.SignerProvider;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.interfaces.ECPublicKey;
import java.util.Optional;
import java.util.Set;

import org.apache.tuweni.bytes.Bytes;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.web3j.crypto.Keys;

public class AddressIndexedSignerProviderTest {

  @Test
  public void returnsSignerForAddress()
      throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
    SignerProvider signerProvider = Mockito.mock(SignerProvider.class);

    ECPublicKey key1 = EthPublicKeyUtils.createPublicKey(Keys.createEcKeyPair().getPublicKey());

    Mockito.doReturn(Set.of(key1)).when(signerProvider).availablePublicKeys();
    Mockito.doReturn(Optional.of(Mockito.mock(Signer.class))).when(signerProvider).getSigner(key1);
    AddressIndexedSignerProvider addressIndexedSignerProvider =
        AddressIndexedSignerProvider.create(signerProvider);
    assertThat(
        addressIndexedSignerProvider
            .getSigner(
                "0x"
                    + Keys.getAddress(
                        Bytes.wrap(EthPublicKeyUtils.toByteArray(key1)).toHexString()))
            .isPresent());
  }

  @Test
  public void returnsSignerForAddedAddress()
      throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
    SignerProvider signerProvider = Mockito.mock(SignerProvider.class);

    ECPublicKey key1 = EthPublicKeyUtils.createPublicKey(Keys.createEcKeyPair().getPublicKey());
    ECPublicKey key2 = EthPublicKeyUtils.createPublicKey(Keys.createEcKeyPair().getPublicKey());

    Mockito.doReturn(Set.of(key1)).when(signerProvider).availablePublicKeys();
    Mockito.doReturn(Optional.of(Mockito.mock(Signer.class))).when(signerProvider).getSigner(key1);

    AddressIndexedSignerProvider addressIndexedSignerProvider =
        AddressIndexedSignerProvider.create(signerProvider);
    assertThat(
        addressIndexedSignerProvider
            .getSigner(
                "0x"
                    + Keys.getAddress(
                        Bytes.wrap(EthPublicKeyUtils.toByteArray(key1)).toHexString()))
            .isPresent());
    assertThat(
        !addressIndexedSignerProvider
            .getSigner(
                "0x"
                    + Keys.getAddress(
                        Bytes.wrap(EthPublicKeyUtils.toByteArray(key2)).toHexString()))
            .isPresent());

    Mockito.doReturn(Set.of(key1, key2)).when(signerProvider).availablePublicKeys();
    Mockito.doReturn(Optional.of(Mockito.mock(Signer.class))).when(signerProvider).getSigner(key2);

    assertThat(
        addressIndexedSignerProvider
            .getSigner(
                "0x"
                    + Keys.getAddress(
                        Bytes.wrap(EthPublicKeyUtils.toByteArray(key1)).toHexString()))
            .isPresent());
    assertThat(
        addressIndexedSignerProvider
            .getSigner(
                "0x"
                    + Keys.getAddress(
                        Bytes.wrap(EthPublicKeyUtils.toByteArray(key2)).toHexString()))
            .isPresent());
  }
}
