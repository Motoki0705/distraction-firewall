using DistractionFirewall.Contracts;

namespace DistractionFirewall.App.ViewModels;

public sealed class TargetChoiceViewModel : ObservableObject
{
    private readonly Action _changed;
    private bool _isSelected;

    public TargetChoiceViewModel(TargetDescriptor target, Action changed)
    {
        Target = target;
        _changed = changed;
    }

    public TargetDescriptor Target { get; }

    public bool IsSelected
    {
        get => _isSelected;
        set
        {
            if (SetProperty(ref _isSelected, value))
            {
                _changed();
            }
        }
    }
}

public sealed record DurationChoice(string Label, int? Minutes);

public sealed record OffsetChoice(string Label, TimeSpan Offset);
