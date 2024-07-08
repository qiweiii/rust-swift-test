#include <cstdarg>
#include <cstdint>
#include <cstdlib>
#include <ostream>
#include <new>

template<typename T = void>
struct Vec;

struct Prover {
  uintptr_t prover_idx;
  Secret secret;
  Vec<Public> ring;
};

extern "C" {

const RingContext *ring_context();

Prover new(Vec<Public> ring, uintptr_t prover_idx);

} // extern "C"
