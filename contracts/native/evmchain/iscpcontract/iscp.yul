object "ISCPYul" {
  code {
    switch selector()
    case 0x0c49c36c /* "sayHi()" */ {
      verbatim_0i_0o(hex"c0")
    }
    default {
      revert(0, 0)
    }

    function selector() -> s {
        s := div(calldataload(0), 0x100000000000000000000000000000000000000000000000000000000)
    }
  }
}
