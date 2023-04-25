// Copyright (c) 2023 Haofan Zheng
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

#pragma once


#include <SimpleSysIO/StreamSocketBase.hpp>


namespace DecentEnclaveServer
{

void HandleAppCertRequest(
	std::unique_ptr<SimpleSysIO::StreamSocketBase> socket
);

} // namespace DecentEnclaveServer
