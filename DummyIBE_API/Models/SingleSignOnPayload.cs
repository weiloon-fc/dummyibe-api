namespace DummyIBE_API.Models
{
    public class SingleSignOnPayload
    {
        public string? IPCC { get; set; }
        public string? EPR { get; set; }
        public string? Passcode { get; set; }
        public string? SabreAuthToken { get; set; }
        public string RefId { get; set; } = null!;
        public string POS { get; set; } = null!;
        public string Language { get; set; } = null!;
        public string? LogoUrl { get; set; }
        public int ShowFreeSeatsOnly { get; set; }
        public string? RedirectUrl { get; set; }
        public string? CallbackUrl { get; set; }
        public int Method { get; set; }
        public int Environment { get; set; }
        public string? PNR { get; set; }
        public string? Currency { get; set; }
        public bool? IsAutoUpdatePNR { get; set; }

        public int MarkupMethod { get; set; }
        public decimal MarkupPercentage { get; set; }
        public decimal MarkupAmount { get; set; }

        public List<SingleSignOnFlightModel>? Flights { get; set; }
        public List<SingleSignOnPassengerModel>? Passengers { get; set; }
    }

    public class SingleSignOnFlightModel
    {
        public string OriginCity { get; set; } = null!;
        public string DestinationCity { get; set; } = null!;
        public string DepartureDate { get; set; } = null!;
        public string ArrivalDate { get; set; } = null!;
        public string AirlineCode { get; set; } = null!;
        public string FlightNo { get; set; } = null!;
        public string OperatingAirlineCode { get; set; } = null!;
        public string OperatingFlightNo { get; set; } = null!;
        public string RBD { get; set; } = null!;
        public string CabinCode { get; set; } = null!;
        public List<SingleSignOnPassengerPreSelectedSeat> PreSelectedSeat { get; set; } = new List<SingleSignOnPassengerPreSelectedSeat>();
    }

    public class SingleSignOnPassengerModel
    {
        public int Id { get; set; }
        public string FirstName { get; set; } = null!;
        public string LastName { get; set; } = null!;
        public string PaxType { get; set; } = null!;
        public bool WithInfants { get; set; }
        public SingleSignOnPassengerFrequentFlyerNumberModel? FrequentFlyer { get; set; }
    }

    public class SingleSignOnPassengerFrequentFlyerNumberModel
    {
        public string CarrierCode { get; set; } = null!;
        public string Number { get; set; } = null!;
    }

    public class SingleSignOnPassengerPreSelectedSeat
    {
        public int PassengerId { get; set; }
        public int Row { get; set; }
        public string Column { get; set; } = null!;
    }

    public enum EnumMarkupMethod
    {
        None = 0,
        Percentage = 1,
        Amount = 2,
        PercentageAndAmount = 3
    }
}
