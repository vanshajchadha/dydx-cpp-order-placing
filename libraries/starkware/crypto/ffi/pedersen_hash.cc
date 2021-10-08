#include <array>

#include "third_party/gsl/gsl-lite.hpp"

#include "starkware/algebra/prime_field_element.h"
#include "starkware/crypto/ffi/utils.h"
#include "starkware/crypto/pedersen_hash.h"

namespace starkware {

namespace {

using ValueType = PrimeFieldElement::ValueType;

constexpr size_t element_size = sizeof(ValueType);
constexpr size_t output_buffer_size = 1024;
static_assert(output_buffer_size >= element_size, "output_buffer_size is not big enough");

}  // namespace

extern "C" int Hash(
    const gsl::byte in1[element_size], const gsl::byte in2[element_size],
    gsl::byte out[output_buffer_size]) {
  try {
    auto hash = PedersenHash(
        PrimeFieldElement::FromBigInt(Deserialize(gsl::make_span(in1, element_size))),
        PrimeFieldElement::FromBigInt(Deserialize(gsl::make_span(in2, element_size))));
    Serialize(hash.ToStandardForm(), gsl::make_span(out, element_size));
  } catch (const std::exception& e) {
    return HandleError(e.what(), gsl::make_span(out, output_buffer_size));
  } catch (...) {
    return HandleError("Unknown c++ exception.", gsl::make_span(out, output_buffer_size));
  }
  return 0;
}

}  // namespace starkware
