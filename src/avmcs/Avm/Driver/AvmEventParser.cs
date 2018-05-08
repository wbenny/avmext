using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using Unmanaged;

namespace Avm.Driver
{
    public class EventParsedEventArgs : EventArgs
    {
        public AvmEvent ParsedEvent;
    }

    public delegate void EventParsedHandler(object sender, EventParsedEventArgs e);

    public class AvmEventParser
    {

        public AvmEventParser()
        {
            EventList = new List<AvmEvent>();
            FunctionIdToDescriptionMap = new Dictionary<int, AvmEventFunctionCall.FunctionDescription>();
            EnumIdToDescriptionMap = new Dictionary<int, AvmEventFunctionCall.EnumDescription>();
        }

        /// <summary>
        /// Parses as much events as possible from the input buffer.
        /// </summary>
        /// <param name="stream">Event stream</param>
        public void Parse(Stream stream)
        {
            using (var reader = new BinaryReader(stream))
            {
                for (;;)
                {
                    var size = reader.ReadUInt32();
                    var sequenceId = reader.ReadUInt32();
                    var type = (EventType)reader.ReadUInt32();

                    AvmEvent parsedEvent = null;
                    EventParsedHandlerInternal handler;

                    switch (type)
                    {
                        case EventType.FunctionCall:
                            parsedEvent = AvmEventFunctionCall.Parse(reader);
                            CacheDescriptions((AvmEventFunctionCall)parsedEvent);
                            handler = OnParseFunctionCallEvent;
                            break;

                        case EventType.Process:
                            parsedEvent = AvmEventProcess.Parse(reader);
                            handler = OnParseProcessEvent;
                            break;

                        case EventType.Thread:
                            parsedEvent = AvmEventThread.Parse(reader);
                            handler = OnParseThreadEvent;
                            break;

                        case EventType.LoadImage:
                            parsedEvent = AvmEventLoadImage.Parse(reader);
                            handler = OnParseLoadImageEvent;
                            break;

                        default:
                            throw new InvalidDataException();
                    }

                    parsedEvent.Size = size;
                    parsedEvent.SequenceId = sequenceId;
                    parsedEvent.Type = type;

                    EventList.Add(parsedEvent);
                    handler(new EventParsedEventArgs { ParsedEvent = parsedEvent });
                }
            }
        }

        /// <summary>
        /// Puts FunctionDescription and EnumDescription to the cache.
        /// </summary>
        /// <param name="functionCallEvent">FunctionCall event to cache descriptions from</param>
        private void CacheDescriptions(AvmEventFunctionCall functionCallEvent)
        {
            //
            // If FunctionDescription is set, cache it.
            // If FunctionDescription is not set, find it in the cache.
            //
            if (functionCallEvent.Description != null)
            {
                FunctionIdToDescriptionMap[functionCallEvent.FunctionId] = functionCallEvent.Description;
            }
            else
            {
                functionCallEvent.Description = FunctionIdToDescriptionMap[functionCallEvent.FunctionId];
            }

            //
            // Traverse through all parameter values.
            //
            for (int i = 0; i < functionCallEvent.ParameterValues.Count; i++)
            {
                var functionParameter = functionCallEvent.Description.FunctionParameters[i];

                if (functionCallEvent.ParameterValues[i].Hints.HasFlag(VariantHint.Enum))
                {
                    //
                    // If EnumDescription is set, cache it.
                    // If EnumDescription is not set, find it in the cache.
                    //
                    if (functionParameter.EnumDescription != null)
                    {
                        EnumIdToDescriptionMap[functionParameter.EnumDescription.Id] = functionParameter.EnumDescription;

                        //
                        // Treat NTSTATUS as a special enum and cache it in standalone member variable.
                        //
                        if (NtStatusMap == null &&
                            functionParameter.EnumDescription.Name == "NTSTATUS")
                        {
                            NtStatusMap = functionParameter.EnumDescription.ItemMap;
                        }
                    }
                    else
                    {
                        functionParameter.EnumDescription = EnumIdToDescriptionMap[functionCallEvent.ParameterValues[i].EnumId];
                    }
                }
            }
        }

        /// <summary>
        /// Tries to convert NTSTATUS error code to its string representation.
        /// If provided error code is not recognized, the value is represented
        /// as hex number.
        /// </summary>
        /// <param name="status">NTSTATUS value</param>
        /// <returns>String representation of NTSTATUS value</returns>
        public string FormatNTSTATUS(uint status)
        {
            string result;
            if (!NtStatusMap.TryGetValue(status, out result))
            {
                result = string.Format("{0:X8}", status);
            }

            return result;
        }

        public string GetDosPathFromNtPath(string ntPath)
        {
            var logicalDrives = Environment.GetLogicalDrives();

            foreach (var logicalDrive in logicalDrives)
            {
                int ntVolumeSize = 128;
                var ntVolume = new StringBuilder(ntVolumeSize);

                while (Kernel32.QueryDosDevice(logicalDrive.TrimEnd('\\'), ntVolume, ntVolumeSize) == 0)
                {
                    // ERROR_INSUFFICIENT_BUFFER
                    if (Marshal.GetLastWin32Error() != 122)
                    {
                        return null;
                    }

                    ntVolume = new StringBuilder(ntVolumeSize <<= 2);
                }

                if (string.Compare(ntPath, 0, ntVolume.ToString(), 0, ntVolume.Length, StringComparison.OrdinalIgnoreCase) == 0)
                {
                    return logicalDrive + ntPath.Substring(ntVolume.Length);
                }
            }

            return null;
        }

        protected virtual void OnParseFunctionCallEvent(EventParsedEventArgs e)
        {
            if (FunctionCallEventParsed != null)
            {
                FunctionCallEventParsed(this, e);
            }
        }

        protected virtual void OnParseProcessEvent(EventParsedEventArgs e)
        {
            if (ProcessEventParsed != null)
            {
                ProcessEventParsed(this, e);
            }
        }

        protected virtual void OnParseThreadEvent(EventParsedEventArgs e)
        {
            if (ThreadEventParsed != null)
            {
                ThreadEventParsed(this, e);
            }
        }

        protected virtual void OnParseLoadImageEvent(EventParsedEventArgs e)
        {
            if (LoadImageEventParsed != null)
            {
                LoadImageEventParsed(this, e);
            }
        }

        public event EventParsedHandler FunctionCallEventParsed;
        public event EventParsedHandler ProcessEventParsed;
        public event EventParsedHandler ThreadEventParsed;
        public event EventParsedHandler LoadImageEventParsed;

        /// <summary>
        /// Contains list of all parsed events.
        /// </summary>
        public List<AvmEvent> EventList { get; private set; }

        /// <summary>
        /// Maps FunctionId to FunctionDescription.
        /// </summary>
        public Dictionary<int, AvmEventFunctionCall.FunctionDescription> FunctionIdToDescriptionMap { get; private set; }

        /// <summary>
        /// Maps EnumId to EnumDescription
        /// </summary>
        public Dictionary<int, AvmEventFunctionCall.EnumDescription> EnumIdToDescriptionMap { get; private set; }

        /// <summary>
        /// Maps NTSTATUS values to its string representation.
        /// </summary>
        public Dictionary<uint, string> NtStatusMap { get; private set; }

        /// <summary>
        /// This delegate is used as a function type to On* methods.
        /// </summary>
        /// <param name="e">EventArgs with parsed event</param>
        private delegate void EventParsedHandlerInternal(EventParsedEventArgs e);
    }
}
