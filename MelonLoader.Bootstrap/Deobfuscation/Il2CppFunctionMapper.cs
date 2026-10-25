using AsmResolver;
using AsmResolver.IO;
using AsmResolver.PE;
using AsmResolver.PE.File;
using Iced.Intel;

namespace MelonLoader.Bootstrap.Deobfuscation;

public static class Il2CppFunctionMapper {
    private static readonly (string name, InstructionPredicate[] predicates)[] functionMatchers = {
        ("il2cpp_init", new InstructionPredicate[] {
            new MnemonicPredicate(Mnemonic.Push),
            new MnemonicPredicate(Mnemonic.Sub),
            new MnemonicPredicate(Mnemonic.Mov),
            new MnemonicPredicate(Mnemonic.Lea),
            new MnemonicPredicate(Mnemonic.Xor),
            new MnemonicPredicate(Mnemonic.Call),
            new MnemonicPredicate(Mnemonic.Mov),
            new MnemonicPredicate(Mnemonic.Call),
            new MnemonicPredicate(Mnemonic.Movzx),
            new MnemonicPredicate(Mnemonic.Add),
            new MnemonicPredicate(Mnemonic.Pop),
            new MnemonicPredicate(Mnemonic.Ret)
        }),

        ("il2cpp_runtime_invoke", new InstructionPredicate[] {
            new MnemonicPredicate(Mnemonic.Mov),
            new MnemonicPredicate(Mnemonic.Mov),
            new MnemonicPredicate(Mnemonic.Mov),
            new MnemonicPredicate(Mnemonic.Push),
            new MnemonicPredicate(Mnemonic.Sub),
            new MnemonicPredicate(Mnemonic.Mov),
            new MnemonicPredicate(Mnemonic.Mov),
            new MnemonicPredicate(Mnemonic.Mov),
            new MnemonicPredicate(Mnemonic.Test),
            new MnemonicPredicate(Mnemonic.Je),
            new MnemonicPredicate(Mnemonic.Mov),
            new MnemonicPredicate(Mnemonic.Test),
            new MnemonicPredicate(Mnemonic.Je),
            new MnemonicPredicate(Mnemonic.Cmp),
            new MnemonicPredicate(Mnemonic.Je),
            new MnemonicPredicate(Mnemonic.Mov),
            new MnemonicPredicate(Mnemonic.Cmp),
            new MnemonicPredicate(Mnemonic.Jne),
            new MnemonicPredicate(Mnemonic.Mov),
            new MnemonicPredicate(Mnemonic.Call),
            new MnemonicPredicate(Mnemonic.Mov),
            new MnemonicPredicate(Mnemonic.Mov),
            new MnemonicPredicate(Mnemonic.Mov),
            new MnemonicPredicate(Mnemonic.Call),
            new MnemonicPredicate(Mnemonic.Jmp)
        }),

        // Tiny function, so we have to be very precise
        ("il2cpp_method_get_name", new InstructionPredicate[] {
            new FullPredicate(Instruction.Create(
                Code.Mov_r64_rm64,
                Register.RAX,
                new MemoryOperand(Register.RCX, 0x18)
            )),
            new MnemonicPredicate(Mnemonic.Ret)
        }),

        ("il2cpp_resolve_icall", new InstructionPredicate[] {
            new MnemonicPredicate(Mnemonic.Mov),
            new MnemonicPredicate(Mnemonic.Mov),
            new MnemonicPredicate(Mnemonic.Mov),
            new MnemonicPredicate(Mnemonic.Push),
            new MnemonicPredicate(Mnemonic.Push),
            new MnemonicPredicate(Mnemonic.Push),
            new MnemonicPredicate(Mnemonic.Push),
            new MnemonicPredicate(Mnemonic.Push),
            new MnemonicPredicate(Mnemonic.Mov),
            new MnemonicPredicate(Mnemonic.Sub),
            new MnemonicPredicate(Mnemonic.Mov),
            new MnemonicPredicate(Mnemonic.Xor),
            new MnemonicPredicate(Mnemonic.Xorps),
            new MnemonicPredicate(Mnemonic.Movups),
            new MnemonicPredicate(Mnemonic.Mov),
            new MnemonicPredicate(Mnemonic.Mov),
            new MnemonicPredicate(Mnemonic.Mov),
            new MnemonicPredicate(Mnemonic.Nop),
            new MnemonicPredicate(Mnemonic.Inc),
            new MnemonicPredicate(Mnemonic.Cmp),
            new MnemonicPredicate(Mnemonic.Jne),
            new MnemonicPredicate(Mnemonic.Mov),
            new MnemonicPredicate(Mnemonic.Lea),
            new MnemonicPredicate(Mnemonic.Call),
            new MnemonicPredicate(Mnemonic.Mov),
            new MnemonicPredicate(Mnemonic.Mov),
            new MnemonicPredicate(Mnemonic.Mov),
            new MnemonicPredicate(Mnemonic.Mov),
            new MnemonicPredicate(Mnemonic.Mov),
            new MnemonicPredicate(Mnemonic.Mov),
            new MnemonicPredicate(Mnemonic.Cmp),
            new MnemonicPredicate(Mnemonic.Jne),
            new MnemonicPredicate(Mnemonic.Nop),
            new MnemonicPredicate(Mnemonic.Mov),
            new MnemonicPredicate(Mnemonic.Lea),
            new MnemonicPredicate(Mnemonic.Lea),
            new MnemonicPredicate(Mnemonic.Cmp),
            new MnemonicPredicate(Mnemonic.Cmova),
            new MnemonicPredicate(Mnemonic.Mov),
            new MnemonicPredicate(Mnemonic.Cmp),
            new MnemonicPredicate(Mnemonic.Jbe),
            new MnemonicPredicate(Mnemonic.Mov),
            new MnemonicPredicate(Mnemonic.Mov),
            new MnemonicPredicate(Mnemonic.Cmp),
            new MnemonicPredicate(Mnemonic.Cmovb),
            new MnemonicPredicate(Mnemonic.Call),
            new MnemonicPredicate(Mnemonic.Mov),
            new MnemonicPredicate(Mnemonic.Test),
            new MnemonicPredicate(Mnemonic.Jne),
            new MnemonicPredicate(Mnemonic.Cmp),
            new MnemonicPredicate(Mnemonic.Jae),
            new MnemonicPredicate(Mnemonic.Mov),
            new MnemonicPredicate(Mnemonic.Jmp)
        }),

        ("il2cpp_add_internal_call", new InstructionPredicate[] {
            new MnemonicPredicate(Mnemonic.Mov),
            new MnemonicPredicate(Mnemonic.Mov),
            new MnemonicPredicate(Mnemonic.Mov),
            new MnemonicPredicate(Mnemonic.Mov),
            new MnemonicPredicate(Mnemonic.Push),
            new MnemonicPredicate(Mnemonic.Push),
            new MnemonicPredicate(Mnemonic.Push),
            new MnemonicPredicate(Mnemonic.Push),
            new MnemonicPredicate(Mnemonic.Push),
            new MnemonicPredicate(Mnemonic.Mov),
            new MnemonicPredicate(Mnemonic.Sub),
            new MnemonicPredicate(Mnemonic.Mov),
            new MnemonicPredicate(Mnemonic.Xorps),
            new MnemonicPredicate(Mnemonic.Movups),
            new MnemonicPredicate(Mnemonic.Xor),
            new MnemonicPredicate(Mnemonic.Mov),
            new MnemonicPredicate(Mnemonic.Mov),
            new MnemonicPredicate(Mnemonic.Mov),
            new MnemonicPredicate(Mnemonic.Inc),
            new MnemonicPredicate(Mnemonic.Cmp),
            new MnemonicPredicate(Mnemonic.Jne),
            new MnemonicPredicate(Mnemonic.Mov),
            new MnemonicPredicate(Mnemonic.Lea),
            new MnemonicPredicate(Mnemonic.Call),
            new MnemonicPredicate(Mnemonic.Nop),
            new MnemonicPredicate(Mnemonic.Mov),
            new MnemonicPredicate(Mnemonic.Mov),
            new MnemonicPredicate(Mnemonic.Mov),
            new MnemonicPredicate(Mnemonic.Mov),
            new MnemonicPredicate(Mnemonic.Mov),
            new MnemonicPredicate(Mnemonic.Mov),
            new MnemonicPredicate(Mnemonic.Mov),
            new MnemonicPredicate(Mnemonic.Mov),
            new MnemonicPredicate(Mnemonic.Cmp),
            new MnemonicPredicate(Mnemonic.Jne),
            new MnemonicPredicate(Mnemonic.Nop),
            new MnemonicPredicate(Mnemonic.Mov),
            new MnemonicPredicate(Mnemonic.Lea),
            new MnemonicPredicate(Mnemonic.Lea),
            new MnemonicPredicate(Mnemonic.Cmp),
            new MnemonicPredicate(Mnemonic.Cmova),
            new MnemonicPredicate(Mnemonic.Mov),
            new MnemonicPredicate(Mnemonic.Cmp),
            new MnemonicPredicate(Mnemonic.Jbe),
            new MnemonicPredicate(Mnemonic.Mov),
            new MnemonicPredicate(Mnemonic.Mov),
            new MnemonicPredicate(Mnemonic.Cmp),
            new MnemonicPredicate(Mnemonic.Cmovb),
            new MnemonicPredicate(Mnemonic.Call)
        })
    };

    // TODO: Will likely have to implement a more sophisticated thunk matcher in the future
    private static readonly InstructionPredicate[] thunkMatcher = {
        new DelegatedPredicate(instruction =>
            instruction.Mnemonic == Mnemonic.Jmp &&
            instruction.NearBranchTarget != 0
        )
    };

    private static readonly Dictionary<string, string> functionMappings = new ();
    private static readonly Dictionary<string, string> functionMappingsReverse = new ();

    public static void Load() {
        PEFile gameAssemblyFile;
        PEImage gameAssemblyImage;

        try {
            var gameAssemblyPath = Path.Combine(Exports.ProcessDirectory, "GameAssembly.dll");
            gameAssemblyFile = PEFile.FromFile(gameAssemblyPath);
            gameAssemblyImage = PEImage.FromFile(gameAssemblyFile);
        } catch (Exception e) {
            Core.Logger.Error("Failed to open GameAssembly.dll, il2cpp function mapping will not be performed");
            Core.Logger.Error(e.ToString());
            return;
        }

        if (gameAssemblyImage.Exports == null) {
            Core.Logger.Error("Unable to read GameAssembly.dll exports, il2cpp function mapping will not be performed");
            return;
        }

        foreach (var exportedSymbol in gameAssemblyImage.Exports.Entries) {
            if (exportedSymbol.Name == null) continue;

            var reference = exportedSymbol.GetReference();

            if (!reference.CanRead) continue;

            var walker = InstructionWalker.Create(reference);

            // If the export is a thunk, find the actual function and match against that instead
            if (MatchInstructions(walker, thunkMatcher)) {
                var target = walker.instructions[0].NearBranchTarget;
                var newReference = gameAssemblyFile.GetReferenceToRva((uint) target);

                walker = InstructionWalker.Create(newReference);
            }

            foreach (var functionMatcher in functionMatchers) {
                if (functionMappings.ContainsKey(functionMatcher.name)) continue;

                if (!MatchInstructions(walker, functionMatcher.predicates)) continue;

                functionMappings[functionMatcher.name] = exportedSymbol.Name;
                functionMappingsReverse[exportedSymbol.Name] = functionMatcher.name;

                MelonDebug.Log($"Mapping {functionMatcher.name} to {exportedSymbol.Name}");
            }
        }
    }

    public static string Map(string name) {
        if (functionMappings.TryGetValue(name, out var mapped)) return mapped;

        MelonDebug.Log($"No mapping for {name}");

        return name;
    }

    public static string Unmap(string name) {
        return functionMappingsReverse.GetValueOrDefault(name, name);
    }

    private static bool MatchInstructions(InstructionWalker walker, params InstructionPredicate[] predicates) {
        walker.Rewind();

        foreach (var predicate in predicates) {
            if (!walker.Next(out var instruction)) break;
            if (!predicate.Matches(instruction)) return false;
        }

        return true;
    }

    private class ReaderCodeReader(BinaryStreamReader reader) : CodeReader {
        private BinaryStreamReader reader = reader;

        public override int ReadByte() {
            if (!reader.CanRead(1)) return -1;

            return reader.ReadByte();
        }
    }

    private class InstructionWalker(Decoder decoder) {
        public readonly InstructionList instructions = new ();

        private int index;

        public static InstructionWalker Create(ISegmentReference reference) {
            var reader = reference.CreateReader();
            var decoder = Decoder.Create(64, new ReaderCodeReader(reader));
            var walker = new InstructionWalker(decoder);

            decoder.IP = reference.Rva;

            return walker;
        }

        public void Rewind() {
            index = 0;
        }

        public bool Next(out Instruction instruction) {
            if (instructions.Count == index) {
                decoder.Decode(out instruction);
                instructions.Add(instruction);
            }

            instruction = instructions[index];

            if (instruction.IsInvalid || instruction.Length == 0) return false;

            index++;

            return true;
        }
    }

    private interface InstructionPredicate {
        public bool Matches(in Instruction instruction);
    }

    private readonly struct DelegatedPredicate(Predicate<Instruction> predicate) : InstructionPredicate {
        public bool Matches(in Instruction instruction) {
            return predicate(instruction);
        }
    }

    private readonly struct FullPredicate(Instruction instruction) : InstructionPredicate {
        public bool Matches(in Instruction otherInstruction) {
            return instruction == otherInstruction;
        }
    }

    private readonly struct MnemonicPredicate(Mnemonic mnemonic) : InstructionPredicate {
        public bool Matches(in Instruction instruction) {
            return mnemonic == instruction.Mnemonic;
        }
    }
}