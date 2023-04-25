// Copyright (c) 2023 Haofan Zheng
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.


#include "AppRequestHandler.hpp"

#include <string>
#include <vector>

#include <DecentEnclave/Common/AesGcmStreamSocket.hpp>
#include <DecentEnclave/Common/CertStore.hpp>
#include <DecentEnclave/Common/DecentCerts.hpp>
#include <DecentEnclave/Common/Keyring.hpp>
#include <DecentEnclave/Common/Platform/Print.hpp>
#include <DecentEnclave/Trusted/Sgx/ComponentConnection.hpp>
#include <DecentEnclave/Trusted/Sgx/LaResponder.hpp>
#include <DecentEnclave/Trusted/Sgx/Random.hpp>
#include <mbedTLScpp/X509Req.hpp>
#include <SimpleObjects/Internal/make_unique.hpp>
#include <SimpleObjects/ToString.hpp>


void DecentEnclaveServer::HandleAppCertRequest(
	std::unique_ptr<SimpleSysIO::StreamSocketBase> socket
)
{
	using LaResponder = DecentEnclave::Trusted::Sgx::LaResponder;
	using SecSocketWrap = DecentEnclave::Common::AesGcmStreamSocket<128>;
	using RandType = DecentEnclave::Trusted::Sgx::RandGenerator;

	sgx_dh_session_enclave_identity_t peerId;

	auto vrfyCallback = [&peerId](const sgx_dh_session_enclave_identity_t& id) -> void
	{
		peerId = id;
	};

	auto laResp =
		SimpleObjects::Internal::make_unique<LaResponder>(
			vrfyCallback
		);

	auto secSocket =
		SecSocketWrap::FromHandshake(
			std::move(laResp),
			std::move(socket),
			SimpleObjects::Internal::make_unique<RandType>()
		);

	// Receive peer enclave's hash
	const std::vector<uint8_t> peerHash = std::vector<uint8_t>(
		peerId.mr_enclave.m,
		peerId.mr_enclave.m + sizeof(peerId.mr_enclave.m)
	);

	// Receive AppCertRequest
	auto appCertReqAdvRlp = secSocket->SizedRecvBytes<std::vector<uint8_t> >();
	auto appCertReq =
		DecentEnclave::Common::AppCertRequestParser().Parse(appCertReqAdvRlp);

	// Data from AppCertRequest
	const std::string keyName = appCertReq.GetKeyName();
	const std::vector<uint8_t> authList = appCertReq.GetAuthList();
	const std::vector<uint8_t> csrDer = appCertReq.GetCSR();

	// X.509 CSR parsing and verification
	mbedTLScpp::X509Req csr =
		mbedTLScpp::X509Req::FromDER(mbedTLScpp::CtnFullR(csrDer));
	csr.VerifySignature();

	// Get CA key and certificate
	const auto& keyring = DecentEnclave::Common::Keyring::GetInstance();
	const auto& caKey = keyring[keyName].GetPkey();

	const auto& certStore = DecentEnclave::Common::CertStore::GetInstance();
	auto caCert = certStore[keyName].GetCertBase();

	// Issue App certificate
	RandType rand;
	auto appCert = DecentEnclave::Common::IssueAppCert(
		*caCert,
		caKey,
		csr.BorrowPublicKey(),
		keyName,
		peerHash,
		authList,
		rand
	);

	// Send App certificate and CA certificate
	secSocket->SizedSendBytes(appCert.GetPem()); //caCert->GetPem() +

	std::string peerHashHex;
	SimpleObjects::Internal::BytesToHEX<false, char>(
		std::back_inserter(peerHashHex),
		peerHash.begin(),
		peerHash.end()
	);
	DecentEnclave::Common::Platform::Print::StrInfo(
		"App certificate issued to " + peerHashHex + " with key " + keyName
	);
}
