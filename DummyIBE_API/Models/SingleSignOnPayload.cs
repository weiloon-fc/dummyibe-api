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

        public string? RedirectUrl { get; set; }
        public string? CallbackUrl { get; set; }

        public List<SingleSignOnFlightModel> Flights { get; set; } = null!;
        public List<SingleSignOnPassengerModel> Passengers { get; set; } = null!;
    }

    public class SingleSignOnFlightModel
    {
        public string OriginCity { get; set; } = null!;
        public string DestinationCity { get; set; } = null!;
        public string DepartureDate { get; set; } = null!;
        public string AirlineCode { get; set; } = null!;
        public string FlightNo { get; set; } = null!;
        public string RBD { get; set; } = null!;
        public string CabinCode { get; set; } = null!;
    }

    public class SingleSignOnPassengerModel
    {
        public int Id { get; set; }
        public string FirstName { get; set; } = null!;
        public string LastName { get; set; } = null!;
        public string PaxType { get; set; } = null!;
        public SingleSignOnPassengerFrequentFlyerNumberModel? FrequentFlyer { get; set; }
    }

    public class SingleSignOnPassengerFrequentFlyerNumberModel
    {
        public string CarrierCode { get; set; } = null!;
        public string Number { get; set; } = null!;
    }
}
