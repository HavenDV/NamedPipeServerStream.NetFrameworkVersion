using System.Security;
#if NETSTANDARD2_0
using System.Globalization;
using Microsoft.Win32.SafeHandles;
using System.Runtime.InteropServices;
using System.Security.Permissions;
using System.Text;
#endif

namespace System.IO.Pipes;

/// <summary>
/// Original .Net Framework <see cref="NamedPipeServerStream"/> constructors from decompiled code
/// </summary>
[SecurityCritical]
public static class NamedPipeServerStreamConstructors
{
#if NETFRAMEWORK
    /// <inheritdoc cref="NamedPipeServerStream(string, PipeDirection, int, PipeTransmissionMode, PipeOptions, int, int, PipeSecurity, HandleInheritability, PipeAccessRights)"/>
#elif NET5_0_OR_GREATER
/// <inheritdoc cref="NamedPipeServerStreamAcl.Create"/>
#else
    /// <summary>
    /// Create a new <see cref="NamedPipeServerStream"/>. All default parameters are copied from the original constructors.
    /// </summary>
    /// <param name="pipeName"></param>
    /// <param name="direction"></param>
    /// <param name="maxNumberOfServerInstances"></param>
    /// <param name="transmissionMode"></param>
    /// <param name="options"></param>
    /// <param name="inBufferSize"></param>
    /// <param name="outBufferSize"></param>
    /// <param name="pipeSecurity"></param>
    /// <param name="inheritability"></param>
    /// <param name="additionalAccessRights"></param>
    /// <returns></returns>
#endif
#if NET5_0_OR_GREATER
    [Runtime.Versioning.SupportedOSPlatform("windows")]
#endif
    [SecurityCritical]
    public unsafe static NamedPipeServerStream New(
        string pipeName,
        PipeDirection direction = PipeDirection.InOut,
        int maxNumberOfServerInstances = 1,
        PipeTransmissionMode transmissionMode = PipeTransmissionMode.Byte,
        PipeOptions options = PipeOptions.None,
        int inBufferSize = 0,
        int outBufferSize = 0,
        PipeSecurity pipeSecurity = null,
        HandleInheritability inheritability = HandleInheritability.None,
        PipeAccessRights additionalAccessRights = 0)
    {
#if NETFRAMEWORK
        return new NamedPipeServerStream(pipeName, direction, maxNumberOfServerInstances, transmissionMode,
            options, inBufferSize, outBufferSize, pipeSecurity, inheritability, additionalAccessRights);
#elif NET5_0_OR_GREATER
        return NamedPipeServerStreamAcl.Create(pipeName, direction, maxNumberOfServerInstances, transmissionMode,
            options, inBufferSize, outBufferSize, pipeSecurity, inheritability, additionalAccessRights);
#else
        switch (pipeName)
        {
            case "":
                throw new ArgumentException(SR.GetString("Argument_NeedNonemptyPipeName"));
            case null:
                throw new ArgumentNullException(nameof(pipeName));
            default:
                if ((options & ~(PipeOptions.WriteThrough | PipeOptions.Asynchronous)) != PipeOptions.None)
                    throw new ArgumentOutOfRangeException(nameof(options), SR.GetString("ArgumentOutOfRange_OptionsInvalid"));
                if (inBufferSize < 0)
                    throw new ArgumentOutOfRangeException(nameof(inBufferSize), SR.GetString("ArgumentOutOfRange_NeedNonNegNum"));
                if ((maxNumberOfServerInstances < 1 || maxNumberOfServerInstances > 254) && maxNumberOfServerInstances != -1)
                    throw new ArgumentOutOfRangeException(nameof(maxNumberOfServerInstances), SR.GetString("ArgumentOutOfRange_MaxNumServerInstances"));
                if (inheritability < HandleInheritability.None || inheritability > HandleInheritability.Inheritable)
                    throw new ArgumentOutOfRangeException(nameof(inheritability), SR.GetString("ArgumentOutOfRange_HandleInheritabilityNoneOrInheritable"));
                if ((additionalAccessRights & ~(PipeAccessRights.ChangePermissions | PipeAccessRights.TakeOwnership | PipeAccessRights.AccessSystemSecurity)) != (PipeAccessRights)0)
                    throw new ArgumentOutOfRangeException(nameof(additionalAccessRights), SR.GetString("ArgumentOutOfRange_AdditionalAccessLimited"));
                if (Environment.OSVersion.Platform == PlatformID.Win32Windows)
                    throw new PlatformNotSupportedException(SR.GetString("PlatformNotSupported_NamedPipeServers"));
                string fullPath = Path.GetFullPath("\\\\.\\pipe\\" + pipeName);
                if (string.Compare(fullPath, "\\\\.\\pipe\\anonymous", StringComparison.OrdinalIgnoreCase) == 0)
                    throw new ArgumentOutOfRangeException(nameof(pipeName), SR.GetString("ArgumentOutOfRange_AnonymousReserved"));
                object pinningHandle = (object)null;
                SECURITY_ATTRIBUTES? secAttrs = GetSecAttrs(inheritability, pipeSecurity, out pinningHandle);
                try
                {
                    int openMode = (int)((PipeOptions)(direction | (maxNumberOfServerInstances == 1 ? (PipeDirection)524288 : (PipeDirection)0)) | options | (PipeOptions)additionalAccessRights);
                    int pipeMode = (int)transmissionMode << 2 | (int)transmissionMode << 1;
                    if (maxNumberOfServerInstances == -1)
                        maxNumberOfServerInstances = (int)byte.MaxValue;
#pragma warning disable CA2000 // Dispose objects before losing scope

                    SafePipeHandle namedPipe;
                    var secAttrsLocal = secAttrs.HasValue ? secAttrs.Value : default;
                    fixed (char* lpNameLocal = fullPath)
                    {
                        var handle = PInvoke.CreateNamedPipe(
                            lpName: lpNameLocal,
                            dwOpenMode: (FILE_FLAGS_AND_ATTRIBUTES)openMode,
                            dwPipeMode: (NAMED_PIPE_MODE)pipeMode,
                            nMaxInstances: (uint)maxNumberOfServerInstances,
                            nOutBufferSize: (uint)outBufferSize,
                            nInBufferSize: (uint)inBufferSize,
                            nDefaultTimeOut: 0,
                            lpSecurityAttributes: secAttrs.HasValue ? &secAttrsLocal : null);

                        namedPipe = new SafePipeHandle(handle, ownsHandle: true);
                    }

#pragma warning restore CA2000 // Dispose objects before losing scope
                    if (namedPipe.IsInvalid)
                        WinIOError(Marshal.GetLastWin32Error(), string.Empty);

                    return new NamedPipeServerStream(direction, (uint)(options & PipeOptions.Asynchronous) > 0U, false, namedPipe);
                }
                finally
                {
                    if (pinningHandle != null)
                        ((GCHandle)pinningHandle).Free();
                }
        }
#endif
    }

#if NETSTANDARD2_0
    [SecurityCritical]
    internal static unsafe SECURITY_ATTRIBUTES? GetSecAttrs(
        HandleInheritability inheritability,
        PipeSecurity pipeSecurity,
        out object pinningHandle)
    {
        pinningHandle = (object)null;
        if ((inheritability & HandleInheritability.Inheritable) != HandleInheritability.None || pipeSecurity != null)
        {
            var securityAttributes = new SECURITY_ATTRIBUTES();
            securityAttributes.nLength = (uint)Marshal.SizeOf<SECURITY_ATTRIBUTES>();
            if ((inheritability & HandleInheritability.Inheritable) != HandleInheritability.None)
                securityAttributes.bInheritHandle = true;
            if (pipeSecurity != null)
            {
                byte[] descriptorBinaryForm = pipeSecurity.GetSecurityDescriptorBinaryForm();
                pinningHandle = (object)GCHandle.Alloc((object)descriptorBinaryForm, GCHandleType.Pinned);
                fixed (byte* numPtr = descriptorBinaryForm)
                    securityAttributes.lpSecurityDescriptor = numPtr;
            }

            return securityAttributes;
        }

        return null;
    }

    [SecurityCritical]
    internal static void WinIOError(int errorCode, string maybeFullPath)
    {
        bool isInvalidPath = errorCode == 123 || errorCode == 161;
        string displayablePath = GetDisplayablePath(maybeFullPath, isInvalidPath);
        switch (errorCode)
        {
            case 2:
                if (displayablePath.Length == 0)
                    throw new FileNotFoundException(SR.GetString("IO_FileNotFound"));
                throw new FileNotFoundException(string.Format((IFormatProvider)CultureInfo.CurrentCulture, SR.GetString("IO_FileNotFound_FileName"), new object[1]
                {
        (object) displayablePath
                }), displayablePath);
            case 3:
                if (displayablePath.Length == 0)
                    throw new DirectoryNotFoundException(SR.GetString("IO_PathNotFound_NoPathName"));
                throw new DirectoryNotFoundException(string.Format((IFormatProvider)CultureInfo.CurrentCulture, SR.GetString("IO_PathNotFound_Path"), new object[1]
                {
        (object) displayablePath
                }));
            case 5:
                if (displayablePath.Length == 0)
                    throw new UnauthorizedAccessException(SR.GetString("UnauthorizedAccess_IODenied_NoPathName"));
                throw new UnauthorizedAccessException(string.Format((IFormatProvider)CultureInfo.CurrentCulture, SR.GetString("UnauthorizedAccess_IODenied_Path"), new object[1]
                {
        (object) displayablePath
                }));
            case 15:
                throw new DriveNotFoundException(string.Format((IFormatProvider)CultureInfo.CurrentCulture, SR.GetString("IO_DriveNotFound_Drive"), new object[1]
                {
        (object) displayablePath
                }));
            case 32:
                if (displayablePath.Length == 0)
                    throw new IOException(SR.GetString("IO_IO_SharingViolation_NoFileName"), MakeHRFromErrorCode(errorCode));
                throw new IOException(SR.GetString("IO_IO_SharingViolation_File", (object)displayablePath), MakeHRFromErrorCode(errorCode));
            case 80:
                if (displayablePath.Length != 0)
                    throw new IOException(string.Format((IFormatProvider)CultureInfo.CurrentCulture, SR.GetString("IO_IO_FileExists_Name"), new object[1]
                    {
          (object) displayablePath
                    }), MakeHRFromErrorCode(errorCode));
                break;
            case 87:
                throw new IOException(GetMessage(errorCode), MakeHRFromErrorCode(errorCode));
            case 183:
                if (displayablePath.Length != 0)
                    throw new IOException(SR.GetString("IO_IO_AlreadyExists_Name", (object)displayablePath), MakeHRFromErrorCode(errorCode));
                break;
            case 206:
                throw new PathTooLongException(SR.GetString("IO_PathTooLong"));
            case 995:
                throw new OperationCanceledException();
        }
        throw new IOException(GetMessage(errorCode), MakeHRFromErrorCode(errorCode));
    }

    [SecuritySafeCritical]
    internal static string GetDisplayablePath(string path, bool isInvalidPath)
    {
        if (string.IsNullOrEmpty(path))
            return path;
        bool flag1 = false;
        if (path.Length < 2)
            return path;
        if ((int)path[0] == (int)Path.DirectorySeparatorChar && (int)path[1] == (int)Path.DirectorySeparatorChar)
            flag1 = true;
        else if ((int)path[1] == (int)Path.VolumeSeparatorChar)
            flag1 = true;
        if (!flag1 && !isInvalidPath)
            return path;
        bool flag2 = false;
        try
        {
            if (!isInvalidPath)
            {
                new FileIOPermission(FileIOPermissionAccess.PathDiscovery, new string[1]
                {
                    path
                }).Demand();
                flag2 = true;
            }
        }
        catch (SecurityException)
        {
        }
        catch (ArgumentException)
        {
        }
        catch (NotSupportedException)
        {
        }
        if (!flag2)
            path = (int)path[path.Length - 1] != (int)Path.DirectorySeparatorChar ? Path.GetFileName(path) : SR.GetString("IO_IO_NoPermissionToDirectoryName");
        return path;
    }

    internal static int MakeHRFromErrorCode(int errorCode)
    {
        return -2147024896 | errorCode;
    }

    internal static readonly IntPtr NULL = IntPtr.Zero;

    [SecurityCritical]
    internal static unsafe string GetMessage(int errorCode)
    {
        var lpBuffer = stackalloc char[512];

        return PInvoke.FormatMessage(
            dwFlags:
                FORMAT_MESSAGE_OPTIONS.FORMAT_MESSAGE_ARGUMENT_ARRAY |
                FORMAT_MESSAGE_OPTIONS.FORMAT_MESSAGE_FROM_SYSTEM |
                FORMAT_MESSAGE_OPTIONS.FORMAT_MESSAGE_IGNORE_INSERTS,
            lpSource: null,
            dwMessageId: (uint)errorCode,
            dwLanguageId: 0,
            lpBuffer: lpBuffer,
            nSize: 512,
            Arguments: null) != 0 ? new string(lpBuffer) : "UnknownError_Num " + (object)errorCode;
    }
#endif
}
