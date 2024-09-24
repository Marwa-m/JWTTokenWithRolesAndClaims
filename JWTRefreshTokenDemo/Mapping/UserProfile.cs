using AutoMapper;
using JWTRefreshTokenDemo.Models;
using JWTRefreshTokenDemo.ViewModels;

namespace JWTRefreshTokenDemo.Mapping
{
    public partial class UserProfile : Profile
    {
        public UserProfile()
        {
            RegisterUserViewModelMapping();
        }
    }

    public partial class UserProfile
    {
        public void RegisterUserViewModelMapping()
        {

            CreateMap<RegisterUserViewModel, ApplicationUser>();

        }
    }
}
