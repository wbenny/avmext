using Avm;
using Avm.Driver;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace avmcs
{
    class Program
    {
        private void OnParseFunctionCallEvent(object sender, EventParsedEventArgs e)
        {
            var eventParser = (AvmEventParser)sender;
            var parsedEvent = (AvmEventFunctionCall)e.ParsedEvent;

            Console.WriteLine("{0}", parsedEvent.Description.FunctionName);
            Console.WriteLine("\tPID:         {0}", parsedEvent.ProcessId);
            Console.WriteLine("\tTID:         {0}", parsedEvent.ThreadId);
            Console.WriteLine("\tReturnValue: {0}", eventParser.FormatNTSTATUS(parsedEvent.ReturnValue));

            for (int i = 0; i < parsedEvent.ParameterValues.Count; i++)
            {
                var parameter = parsedEvent.Description.FunctionParameters[i];
                var parameterVariant = parsedEvent.ParameterValues[i];

                if (parameterVariant.Hints.HasFlag(VariantHint.Enum))
                {
                    Console.WriteLine("\tParameter[{0}]: ({1}) {2}",
                        parameter.ParameterName,
                        parsedEvent.Description.FunctionParameters[i].EnumDescription.Name,
                        parameter.ToString(parameterVariant));
                }
                else
                {
                    Console.WriteLine("\tParameter[{0}]: {1}",
                        parameter.ParameterName,
                        parameter.ToString(parameterVariant));
                }
            }

            Console.WriteLine();
        }

        private void OnParseProcessEvent(object sender, EventParsedEventArgs e)
        {
            var parsedEvent = (AvmEventProcess)e.ParsedEvent;

            Console.WriteLine("Process {0}", parsedEvent.Created ? "creation" : "exit");
            Console.WriteLine("\tPID:         {0}", parsedEvent.ProcessId);
            Console.WriteLine("\tPPID:        {0}", parsedEvent.ParentProcessId);

            if (parsedEvent.Created)
            {
                Console.WriteLine("\tFileName:    {0}", parsedEvent.ImageFileName);
            }

            Console.WriteLine();
        }

        private void OnParseThreadEvent(object sender, EventParsedEventArgs e)
        {
            var parsedEvent = (AvmEventThread)e.ParsedEvent;

            Console.WriteLine("Thread {0}", parsedEvent.Created ? "creation" : "exit");
            Console.WriteLine("\tPID:         {0}", parsedEvent.ProcessId);
            Console.WriteLine("\tTID:         {0}", parsedEvent.ThreadId);
            Console.WriteLine();
        }

        private void OnParseLoadImageEvent(object sender, EventParsedEventArgs e)
        {
            var parsedEvent = (AvmEventLoadImage)e.ParsedEvent;

            Console.WriteLine("Image '{0}'", parsedEvent.ImageFileName);
            Console.WriteLine("\tPID:         {0}", parsedEvent.ProcessId);
            Console.WriteLine("\tImageBase:   {0}", parsedEvent.ImageBase);
            Console.WriteLine("\tImageSize:   {0}", parsedEvent.ImageSize);
            Console.WriteLine();
        }

        private void Run(string[] args)
        {
            AvmEventParser eventParser = new AvmEventParser();
            eventParser.FunctionCallEventParsed += OnParseFunctionCallEvent;
            eventParser.ProcessEventParsed += OnParseProcessEvent;
            eventParser.ThreadEventParsed += OnParseThreadEvent;
            eventParser.LoadImageEventParsed += OnParseLoadImageEvent;

            using (var stream = new BufferedStream(new AvmEventStream()))
            {
                eventParser.Parse(stream);
            }
        }

        static void Main(string[] args)
        {
            (new Program()).Run(args);
        }
    }
}
