namespace DummyIBE_API.Models
{
    public record SelectedSeatPayload(string RefId, List<SelectedSeatPassenger> Passengers, List<SelectedSeatSeatInfo> SelectedSeats);
    public record SelectedSeatPassenger(int Id, string FirstName, string LastName, string PaxType, SelectedSeatPassengerFrequentFlyer FrequentFlyer);
    public record SelectedSeatPassengerFrequentFlyer(string Carrier, string Number);
    public record SelectedSeatSeatInfo(string Carrier, string FlightNo, string OriginCity, string DestinationCity, DateTime DepartureDate, List<SelectedSeatSeatPassengerInfo> Passengers);
    public record SelectedSeatSeatPassengerInfo(int Id, string SeatNumber, int IsAisle, int IsWindow, decimal Fee, string FeeCurrency);
}
