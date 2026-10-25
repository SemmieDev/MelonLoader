using System.Runtime.InteropServices;
using MelonLoader.InternalUtils;

namespace MelonLoader.Deobfuscation;

public static class Il2CppFunctionMapper {
    public static string Map(string name) {
        var remappedNamePtr = BootstrapInterop.Library.MapIl2CppFunction(name, name.Length);
        var remappedName = Marshal.PtrToStringUni(remappedNamePtr);

        Marshal.FreeHGlobal(remappedNamePtr);

        return remappedName;
    }
}