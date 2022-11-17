// Copyright (c) 2022 Haofan Zheng
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.


#include <DecentEnclave/Common/Platform/Print.hpp>
#include <DecentEnclave/Common/Sgx/EpidRaSvcProv.hpp>
#include <DecentEnclave/Common/Sgx/IasReportVerifier.hpp>
#include <DecentEnclave/Common/Sgx/MbedTlsInit.hpp>

#include <DecentEnclave/Trusted/Sgx/EnclaveIdentity.hpp>
#include <DecentEnclave/Trusted/Sgx/EpidRaClient.hpp>
#include <DecentEnclave/Trusted/Sgx/EpidSvcProvAuth.hpp>
#include <DecentEnclave/Trusted/Sgx/IasRequester.hpp>
#include <DecentEnclave/Trusted/Sgx/Random.hpp>

#include <mbedTLScpp/EcKey.hpp>

#include <SimpleObjects/Internal/make_unique.hpp>

#include "Keys.hpp"


using namespace DecentEnclave;
using namespace DecentEnclave::Common;
using namespace DecentEnclave::Common::Sgx;
using namespace DecentEnclave::Trusted;
using namespace DecentEnclave::Trusted::Sgx;

using namespace mbedTLScpp;

namespace DecentEnclaveServer
{

void GlobalInitialization()
{
	// Initialize mbedTLS
	MbedTlsInit::Init();

	// Register keys
	DecentKey_Secp256r1::Register();
	DecentKey_Secp256k1::Register();

	// Lock the keyring, since there is no other key to register
	Keyring::GetInstance().GenKeyHashList();
}

void PrintMyInfo()
{
	const auto& selfHash = EnclaveIdentity::GetSelfHashHex();
	std::string secp256r1KeyFp =
		DecentKey_Secp256r1::GetInstance().GetKeySha256Hex();
	std::string secp256k1KeyFp =
		DecentKey_Secp256k1::GetInstance().GetKeySha256Hex();
	std::string keyringHash = Keyring::GetInstance().GenHashHex();

	Platform::Print::StrInfo(
		"My enclave hash is             : " + selfHash
	);
	Platform::Print::StrInfo(
		"My key fingerprint (SECP256R1) : " + secp256r1KeyFp
	);
	Platform::Print::StrInfo(
		"My key fingerprint (SECP256K1) : " + secp256k1KeyFp
	);
	Platform::Print::StrInfo(
		"My keyring hash is             : " + keyringHash
	);
}

void Init(
	uint64_t enclaveId,
	const sgx_spid_t& spid,
	std::unique_ptr<Common::Sgx::IasRequester> iasRequester
)
{
	GlobalInitialization();

	PrintMyInfo();

	const auto& selfHash = EnclaveIdentity::GetSelfHash();
	auto keyringHash = Keyring::GetInstance().GenHash();
	std::vector<uint8_t> addRepData(keyringHash.cbegin(), keyringHash.cend());

	RandGenerator rand;

	std::unique_ptr<EpidSvcProvAuthAcceptAll> epidAuth =
		SimpleObjects::Internal::make_unique<EpidSvcProvAuthAcceptAll>();

	std::unique_ptr<IasEpidReportVerifier> iasVerifier =
		SimpleObjects::Internal::make_unique<IasEpidReportVerifier>();

	std::unique_ptr<EpidQuoteVerifier> quoteVerifier =
		SimpleObjects::Internal::make_unique<EpidQuoteVerifier>();
	quoteVerifier->SetAddReportData(addRepData);
	quoteVerifier->SetAuthorizedEnclave({ selfHash });

	EpidRaClientCore epidCltCore(
		enclaveId,
		addRepData,
		std::move(epidAuth)
	);
	EpidRaSvcProvCore epidSvrCore(
		DecentKey_Secp256r1::GetKeySharedPtr(),
		spid,
		std::move(iasRequester),
		std::move(iasVerifier),
		std::move(quoteVerifier),
		rand
	);

	auto msg0s = epidCltCore.GetMsg0s();
	auto msg0r = epidSvrCore.GetMsg0r(msg0s);
	auto msg1 = epidCltCore.GetMsg1(msg0r);
	auto msg2 = epidSvrCore.GetMsg2(msg1, rand);
	auto msg3 = epidCltCore.GetMsg3(msg2);
	auto msg4 = epidSvrCore.GetMsg4(msg3);
	epidCltCore.ProcMsg4(msg4);

	Platform::Print::StrDebug(
		std::string("EPID Client Core Handshake - ") +
		(epidCltCore.IsHandshakeDone() ? "Done" :
		(epidCltCore.IsHandshakeRefused() ? "Refused" : "Unknown" ))
	);

	Platform::Print::StrDebug(
		std::string("EPID Service Provider Core Handshake - ") +
		(epidSvrCore.IsHandshakeDone() ? "Done" :
		(epidSvrCore.IsHandshakeRefused() ? "Refused" : "Unknown" ))
	);

	Platform::Print::StrInfo("Decent Server Initialized");
}

} // namespace DecentEnclaveServer

extern "C" sgx_status_t ecall_decent_server_init(
	uint64_t enclaveId,
	const sgx_spid_t* spidPtr,
	void* iasRequesterPtr
)
{
	if (
		spidPtr == nullptr ||
		iasRequesterPtr == nullptr
	)
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}

	sgx_spid_t spid = *spidPtr;

	std::unique_ptr<Trusted::Sgx::IasRequester> iasRequester =
		SimpleObjects::Internal::make_unique<Trusted::Sgx::IasRequester>(
			iasRequesterPtr
		);

	try
	{
		DecentEnclaveServer::Init(
			enclaveId,
			spid,
			std::move(iasRequester)
		);
		return SGX_SUCCESS;
	}
	catch(const std::exception& e)
	{
		Platform::Print::StrErr(e.what());
		return SGX_ERROR_UNEXPECTED;
	}
}
