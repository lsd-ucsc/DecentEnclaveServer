// Copyright (c) 2022 Haofan Zheng
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

#include "DecentServer.hpp"

#include <DecentEnclave/Untrusted/Sgx/IasRequesterImpl.hpp>
#include <DecentEnclave/Common/Sgx/MbedTlsInit.hpp>
#include <SimpleObjects/Internal/make_unique.hpp>

#include <SimpleObjects/SimpleObjects.hpp>
#include <SimpleJson/SimpleJson.hpp>

using namespace DecentEnclave;
using namespace DecentEnclave::Untrusted;
using namespace DecentEnclaveServer;
using namespace SimpleObjects;


int main(int argc, char* argv[]) {
	(void)argc;
	(void)argv;

	// Init MbedTLS
	Common::Sgx::MbedTlsInit::Init();

	sgx_spid_t spid =
		Sgx::IasRequesterImpl::ParseSpid(
			""
		);

	std::unique_ptr<Sgx::IasRequesterImpl> iasReq =
		Internal::make_unique<Sgx::IasRequesterImpl>(
			Sgx::IasRequesterImpl::GetIasUrlDev(),
			""
		);

	DecentServer enclave(spid, std::move(iasReq));
	enclave.Init();

	return 0;
}
